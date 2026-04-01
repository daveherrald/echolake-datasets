# Windows Access Token Winlogon Duplicate Handle In Uncommon Path

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a process attempting to duplicate the handle of winlogon.exe from an uncommon or public source path. This is identified using Sysmon EventCode 10, focusing on processes targeting winlogon.exe with specific access rights and excluding common system paths. This activity is significant because it may indicate an adversary trying to escalate privileges by leveraging the high-privilege tokens associated with winlogon.exe. If confirmed malicious, this could allow the attacker to gain elevated access, potentially leading to full system compromise and persistent control over the affected host.

## MITRE ATT&CK

- T1134.001

## Analytic Stories

- Brute Ratel C4
- PathWiper

## Data Sources

- Sysmon EventID 10

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/brute_ratel/brute_duplicate_token/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_access_token_winlogon_duplicate_handle_in_uncommon_path.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
