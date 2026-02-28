# Wazuh Manager API (for active-response)
WAZUH_API_URL = "https://10.20.1.235:55000"
WAZUH_API_USER = "wazuh"
WAZUH_API_PASS = "kr.GALMW4obBwekg.RR?.A19meZHie*9"

# Wazuh Indexer (OpenSearch) – for alert polling
INDEXER_URL = "https://10.20.1.235:9200"
INDEXER_USER = "admin"
INDEXER_PASS = "gsac9EY*VM212R6YKfszfuoO*BfQE+8s"

# Remediation mapping – use your actual rule IDs from local_rules.xml
REMEDIATION_MAP = {
    100101: None,                                   # Log clear – no action
    100102: {"agent_os": "windows", "action": "disable-local-account"},
    100103: None,                                   # Firewall disable – optional
    100104: {"agent_os": "linux", "action": "disable-local-account"},
    100105: None,                                    # UFW disable – optional
}

# Ollama settings (unchanged)
OLLAMA_URL = "http://ollama:11434/api/generate"
OLLAMA_MODEL = "tinyllama"

