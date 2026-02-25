# Windows Access Token Manipulation SeDebugPrivilege

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a process enabling the "SeDebugPrivilege" privilege token. It leverages Windows Security Event Logs with EventCode 4703, filtering out common legitimate processes. This activity is significant because SeDebugPrivilege allows a process to inspect and modify the memory of other processes, potentially leading to credential dumping or code injection. If confirmed malicious, an attacker could gain extensive control over system processes, enabling them to escalate privileges, persist in the environment, or access sensitive information.

## MITRE ATT&CK

- T1134.002

## Analytic Stories

- Meduza Stealer
- PlugX
- CISA AA23-347A
- China-Nexus Threat Activity
- AsyncRAT
- SnappyBee
- Derusbi
- WinDealer RAT
- Salt Typhoon
- DarkGate Malware
- ValleyRAT
- Brute Ratel C4
- PathWiper
- GhostRedirector IIS Module and Rungan Backdoor
- Lokibot
- Scattered Lapsus$ Hunters
- Tuoni

## Data Sources

- Windows Event Log Security 4703

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/brute_ratel/sedebugprivilege_token/security-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_access_token_manipulation_sedebugprivilege.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
