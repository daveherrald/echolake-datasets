# Non Chrome Process Accessing Chrome Default Dir

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects a non-Chrome process accessing files in the Chrome user default folder. It leverages Windows Security Event logs, specifically event code 4663, to identify unauthorized access attempts. This activity is significant because the Chrome default folder contains sensitive user data such as login credentials, browsing history, and cookies. If confirmed malicious, this behavior could indicate an attempt to exfiltrate sensitive information, often associated with RATs, trojans, and advanced persistent threats like FIN7. Such access could lead to data theft and further compromise of the affected system.

## MITRE ATT&CK

- T1555.003

## Analytic Stories

- StealC Stealer
- CISA AA23-347A
- Phemedrone Stealer
- DarkGate Malware
- NjRAT
- Malicious Inno Setup Loader
- Salt Typhoon
- Remcos
- Warzone RAT
- Quasar RAT
- 3CX Supply Chain Attack
- AgentTesla
- FIN7
- SnappyBee
- RedLine Stealer
- Snake Keylogger
- China-Nexus Threat Activity
- Lokibot

## Data Sources

- Windows Event Log Security 4663

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1555/non_chrome_process_accessing_chrome_default_dir/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/non_chrome_process_accessing_chrome_default_dir.yml)*
