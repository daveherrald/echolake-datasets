# Detect Remote Access Software Usage URL

**Type:** Anomaly

**Author:** Steven Dick

## Description

The following analytic detects the execution of known remote access software within the environment. It leverages network logs mapped to the Web data model, identifying specific URLs and user agents associated with remote access tools like AnyDesk, GoToMyPC, LogMeIn, and TeamViewer. This activity is significant as adversaries often use these utilities to maintain unauthorized remote access. If confirmed malicious, this could allow attackers to control systems remotely, exfiltrate data, or further compromise the network, posing a severe security risk.

## MITRE ATT&CK

- T1219

## Analytic Stories

- Insider Threat
- Command And Control
- Ransomware
- CISA AA24-241A
- Remote Monitoring and Management Software
- Interlock Ransomware
- Scattered Lapsus$ Hunters

## Data Sources

- Palo Alto Network Threat

## Sample Data

- **Source:** screenconnect_palo
  **Sourcetype:** pan:threat
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1219/screenconnect/screenconnect_palo.log


---

*Source: [Splunk Security Content](detections/web/detect_remote_access_software_usage_url.yml)*
