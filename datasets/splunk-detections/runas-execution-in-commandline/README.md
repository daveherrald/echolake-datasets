# Runas Execution in CommandLine

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of the runas.exe process with administrator user options. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions and process details. This activity is significant as it may indicate an attempt to gain elevated privileges, a common tactic in privilege escalation and lateral movement. If confirmed malicious, this could allow an attacker to execute commands with higher privileges, potentially leading to unauthorized access, data exfiltration, or further compromise of the target host.

## MITRE ATT&CK

- T1134.001

## Analytic Stories

- Quasar RAT
- Data Destruction
- Windows Privilege Escalation
- Hermetic Wiper

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/vilsel/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/runas_execution_in_commandline.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
