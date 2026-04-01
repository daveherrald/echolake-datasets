# Excessive Usage Of Cacls App

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying excessive usage of `cacls.exe`, `xcacls.exe`,
or `icacls.exe` to change file or folder permissions.
It looks for 10 or more execution of the aforementioned processes in the span of 1 minute. 
It leverages data from Endpoint Detection and Response (EDR) agents, 
focusing on process names and command-line executions.
This activity is significant as it may indicate an adversary attempting
to restrict access to malware components or artifacts on a compromised system.
If confirmed malicious, this behavior could prevent users from deleting or accessing
critical files, aiding in the persistence and concealment of malicious activities.


## MITRE ATT&CK

- T1222

## Analytic Stories

- Azorult
- Windows Post-Exploitation
- Prestige Ransomware
- XMRig
- Crypto Stealer
- Defense Evasion or Unauthorized Access Via SDDL Tampering

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/excessive_usage_of_cacls_app.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
