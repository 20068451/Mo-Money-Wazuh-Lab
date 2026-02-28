# Mo-Money-Wazuh-Lab
AWS Wazuh lab with AI-based automated remediation for endpoint security assessment
# Mo-Money Wazuh Lab
Endpoint Security Incident Response and Automated Remediation Lab for **Mo Money Group**, built as part of the B9CY110 Communications and Networking Security module (CA One).
This repository contains the infrastructure code, Wazuh configuration snippets, active‑response scripts, and dockerised AI remediation stack used to implement a small but realistic Windows + Linux endpoint security lab in AWS.

---
## 1. Scenario and objectives
Mo Money (operated by Modus Operandi) is a fintech provider in Myanmar offering mobile wallets, interbank transfers, and integrated business solutions. The platform processes sensitive financial transactions, salary payments, and KYC data across a distributed network of agents and merchants, so endpoint security is critical.
After identifying risks around credential theft, unauthorised access, and misused administrator sessions, Mo Money needs better visibility and standardised incident response on Windows and Linux systems.

**Lab objective**
Design and implement an endpoint security monitoring architecture that:
- Collects telemetry from **one Windows Server 2022 endpoint** and **one Ubuntu Linux endpoint**.
- Forwards events into a **Wazuh SIEM** running on Ubuntu.
- Uses **five custom detections** mapped to MITRE ATT&CK.
- Uses a **dockerised Ollama AI stack** to summarise alerts and trigger **predefined, allow‑listed remediation actions**.

Out of scope: full network redesign, enterprise EDR roll‑out, ticketing/SOAR integration, and any testing on production systems.

## 2. Architecture overview
The lab runs in AWS and was provisioned using Terraform (IaC).
- **Network**
  - Custom VPC with private subnet (10.20.1.0/24).
  - Security groups follow least‑privilege:
    - Wazuh server: SSH (for build only), HTTPS for dashboard, Wazuh ports 1514/1515/9200.
    - Windows endpoint: RDP, outbound to Wazuh.
    - Linux endpoint: SSH, outbound to Wazuh.
- **Instances**
  - **Wazuh SIEM server** – Ubuntu, runs manager, indexer, and dashboard.
  - **Windows endpoint** – Windows Server 2022.
  - **Linux endpoint** – Ubuntu Server.
- **Access**
  - Administrative access via **AWS Systems Manager Session Manager (SSM)** to all instances (no direct internet‑exposed SSH/RDP in steady state).
  - Wazuh dashboard reachable via HTTPS through an SSH/SSM tunnel.
- **Weak baseline (controlled)**
  - Windows: `labuser` local account to simulate low‑privilege misuse and elevation attempts.
  - Linux: `labuser` added to `sudo` to model weak privilege separation.
Time synchronisation uses NTP on Linux (`timedatectl`) and Windows Time Service (`w32tm`) to keep timestamps aligned across logs.

---

## 3. Repository layout
.
├── iac/                       # Terraform for AWS VPC + EC2 instances
├── wazuh/
│   └── local_rules.xml        # Custom Wazuh rules (100101–100105)
├── ai-remediation/
│   ├── docker-compose.yml     # Ollama + ai-remediation stack
│   └── ai-service/
│       ├── app.py             # Main AI remediation service
│       ├── config.py          # WAZUH/INDEXER URLs + REMEDIATION_MAP (no real secrets)
│       ├── requirements.txt
│       └── ...
├── scripts/
│   ├── windows/
│   │   ├── Disable-LocalUser.ps1
│   └── linux/
│       ├── disable_user.sh
└── README.md
