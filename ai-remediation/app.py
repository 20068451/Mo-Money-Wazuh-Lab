import time
import requests
import logging
from config import *

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
requests.packages.urllib3.disable_warnings()

# ---------- Wazuh Manager API (with token refresh) ----------
manager_session = requests.Session()
manager_session.verify = False
token = None
token_expiry = 0  # timestamp when token expires

def get_manager_token(force=False):
    global token, token_expiry
    now = time.time()
    # Refresh if no token, expired, or forced
    if not force and token and token_expiry > now + 60:
        return token
    url = f"{WAZUH_API_URL}/security/user/authenticate?raw=true"
    try:
        resp = requests.get(url, auth=(WAZUH_API_USER, WAZUH_API_PASS), verify=False)
        if resp.status_code == 200:
            token = resp.text.strip()
            token_expiry = now + 900  # tokens valid 15 min, set expiry a bit earlier
            logging.info("Manager API token refreshed successfully")
            manager_session.headers.update({"Authorization": f"Bearer {token}"})
            return token
        else:
            logging.error(f"Failed to get token: {resp.status_code} - {resp.text}")
            return None
    except Exception as e:
        logging.error(f"Exception getting token: {e}")
        return None

# Initial token
if not get_manager_token():
    exit(1)

def trigger_active_response(agent_id, command, arguments):
    # Ensure token is still valid
    get_manager_token()

    url = f"{WAZUH_API_URL}/active-response"
    params = {"agents_list": agent_id}

    if not command.startswith('!'):
        cmd = f"!{command}"
    else:
        cmd = command

    payload = {
        "command": cmd,
        "arguments": arguments
    }

    try:
        resp = manager_session.put(url, params=params, json=payload, timeout=10)
        if resp.status_code == 200:
            logging.info(f"✅ AR triggered: {command} on agent {agent_id} with args {arguments}")
            return True
        elif resp.status_code == 401:
            # Token expired, refresh and retry once
            logging.warning("Token expired, refreshing and retrying...")
            if get_manager_token(force=True):
                resp = manager_session.put(url, params=params, json=payload, timeout=10)
                if resp.status_code == 200:
                    logging.info(f"✅ AR triggered (after refresh): {command} on agent {agent_id} with args {arguments}")
                    return True
                else:
                    logging.error(f"AR failed after refresh: {resp.status_code} - {resp.text}")
                    return False
            else:
                logging.error("Could not refresh token")
                return False
        else:
            logging.error(f"AR failed: {resp.status_code} - {resp.text}")
            return False
    except Exception as e:
        logging.error(f"Exception in AR trigger: {e}")
        return False

# ---------- Indexer (OpenSearch) polling for alerts ----------
indexer_session = requests.Session()
indexer_session.auth = (INDEXER_USER, INDEXER_PASS)
indexer_session.verify = False

last_timestamp = None

def get_new_alerts_from_indexer():
    global last_timestamp
    query = {
        "size": 20,
        "sort": [{"timestamp": {"order": "asc"}}],
        "query": {
            "range": {
                "timestamp": {
                    "gte": "now-5m"
                }
            }
        }
    }
    if last_timestamp:
        query["query"]["range"]["timestamp"]["gt"] = last_timestamp

    url = f"{INDEXER_URL}/wazuh-alerts-*/_search"
    try:
        resp = indexer_session.post(url, json=query, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            hits = data.get("hits", {}).get("hits", [])
            if hits:
                latest = hits[-1]["_source"]["timestamp"]
                if not last_timestamp or latest > last_timestamp:
                    last_timestamp = latest
            return hits
        else:
            logging.error(f"Indexer query error: {resp.status_code} - {resp.text}")
            return []
    except Exception as e:
        logging.error(f"Indexer exception: {e}")
        return []

def extract_username_from_alert(alert_source, agent_os):
    data = alert_source.get("data", {})
    if agent_os == "windows":
        eventdata = data.get("win", {}).get("eventdata", {})
        return (eventdata.get("targetUserName") or
                eventdata.get("samAccountName") or
                eventdata.get("TargetUserName"))
    else:
        # Linux: try multiple common fields (dstuser, user, etc.)
        return (data.get("dstuser") or
                data.get("user") or
                data.get("audit", {}).get("user", {}).get("name") or
                data.get("data", {}).get("user"))
    return None

def summarize_with_ai(description):
    prompt = f"Summarize this security alert in one sentence:\n{description}"
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False
    }
    try:
        resp = requests.post(OLLAMA_URL, json=payload, timeout=30)
        if resp.status_code == 200:
            return resp.json().get("response", "").strip()
    except Exception as e:
        logging.error(f"AI call failed: {e}")
    return "AI summary unavailable"

def main():
    logging.info("AI Remediation Service Started (polling indexer)")
    while True:
        alerts = get_new_alerts_from_indexer()
        for hit in alerts:
            source = hit["_source"]
            rule_id = source.get("rule", {}).get("id")
            description = source.get("rule", {}).get("description", "")
            agent = source.get("agent", {})
            agent_id = agent.get("id")

            # Determine OS type robustly
            agent_os = ""
            os_info = agent.get("os", {})
            if os_info:
                agent_os = os_info.get("type") or os_info.get("platform") or os_info.get("name") or ""
            if not agent_os:
                groups = source.get("rule", {}).get("groups", [])
                if any("windows" in g.lower() for g in groups):
                    agent_os = "windows"
                elif any("linux" in g.lower() for g in groups):
                    agent_os = "linux"
            agent_os = agent_os.lower()

            timestamp = source.get("timestamp")

            logging.info(f"Processing alert {rule_id} from agent {agent_id} at {timestamp}")
            logging.info(f"DEBUG rule_id: {rule_id} (type: {type(rule_id)})")
            logging.info(f"DEBUG agent_os: '{agent_os}'")

            # AI summary
            summary = summarize_with_ai(description)
            logging.info(f"AI summary: {summary}")

            # Check remediation map
            rule_id_int = int(rule_id) if rule_id is not None else None
            action_info = REMEDIATION_MAP.get(rule_id_int)
            logging.info(f"DEBUG action_info for rule {rule_id} (int: {rule_id_int}): {action_info}")

            if action_info and action_info.get("agent_os") == agent_os:
                username = extract_username_from_alert(source, agent_os)
                if username:
                    logging.info(f"Attempting remediation: {action_info['action']} for user {username}")
                    trigger_active_response(agent_id, action_info["action"], [username])
                else:
                    logging.warning("Username not found in alert, cannot remediate")
            else:
                if action_info:
                    logging.info(f"Remediation skipped: agent_os '{agent_os}' != expected '{action_info.get('agent_os')}'")
                else:
                    logging.info("No remediation mapped for this alert")

        time.sleep(10)

if __name__ == "__main__":
    main()
