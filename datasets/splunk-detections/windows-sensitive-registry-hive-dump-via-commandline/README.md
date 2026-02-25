# Windows Sensitive Registry Hive Dump Via CommandLine

**Type:** TTP

**Author:** Michael Haag, Patrick Bareiss, Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting the use of `reg.exe` to export Windows Registry hives, which may contain sensitive credentials. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions involving `save` or `export` actions targeting the `sam`, `system`, or `security` hives. This activity is significant as it indicates potential offline credential access attacks, often executed from untrusted processes or scripts. If confirmed malicious, attackers could gain access to credential data, enabling further compromise and lateral movement within the network.

## MITRE ATT&CK

- T1003.002

## Analytic Stories

- CISA AA22-257A
- CISA AA23-347A
- Compromised Windows Host
- Credential Dumping
- DarkSide Ransomware
- Data Destruction
- Industroyer2
- Volt Typhoon
- Windows Registry Abuse
- Seashell Blizzard

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.002/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_sensitive_registry_hive_dump_via_commandline.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
