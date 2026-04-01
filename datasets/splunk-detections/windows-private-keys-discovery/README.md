# Windows Private Keys Discovery

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying processes that retrieve information related to private key files, often used by post-exploitation tools like winpeas. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions that search for private key certificates. This activity is significant as it indicates potential attempts to locate insecurely stored credentials, which adversaries can exploit for privilege escalation, persistence, or remote service authentication. If confirmed malicious, this behavior could allow attackers to access sensitive information, escalate privileges, or maintain persistence within the compromised environment.

## MITRE ATT&CK

- T1552.004

## Analytic Stories

- Windows Post-Exploitation
- Prestige Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/winpeas/winpeas_search_private_key/dir-private-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_private_keys_discovery.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
