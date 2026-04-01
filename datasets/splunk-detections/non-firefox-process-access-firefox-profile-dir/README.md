# Non Firefox Process Access Firefox Profile Dir

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting non-Firefox processes accessing the Firefox profile directory, which contains sensitive user data such as login credentials, browsing history, and cookies. It leverages Windows Security Event logs, specifically event code 4663, to monitor access attempts. This activity is significant because it may indicate attempts by malware, such as RATs or trojans, to harvest user information. If confirmed malicious, this behavior could lead to data exfiltration, unauthorized access to user accounts, and further compromise of the affected system.

## MITRE ATT&CK

- T1555.003

## Analytic Stories

- StealC Stealer
- DarkGate Malware
- CISA AA23-347A
- NjRAT
- Phemedrone Stealer
- Azorult
- Salt Typhoon
- Remcos
- Warzone RAT
- Quasar RAT
- 3CX Supply Chain Attack
- AgentTesla
- RedLine Stealer
- SnappyBee
- Malicious Inno Setup Loader
- FIN7
- Snake Keylogger
- China-Nexus Threat Activity
- 0bj3ctivity Stealer
- Lokibot

## Data Sources

- Windows Event Log Security 4663

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1555/non_chrome_process_accessing_chrome_default_dir/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/non_firefox_process_access_firefox_profile_dir.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
