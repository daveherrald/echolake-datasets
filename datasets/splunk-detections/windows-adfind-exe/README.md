# Windows AdFind Exe

**Type:** TTP

**Author:** Jose Hernandez, Bhavin Patel, Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for identifying the execution of `adfind.exe` standalone or with specific command-line arguments related to Active Directory queries. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names, command-line arguments, and parent Processes. This activity is significant because `adfind.exe` is a powerful tool often used by threat actors like Wizard Spider and FIN6 to gather sensitive AD information. If confirmed malicious, this activity could allow attackers to map the AD environment, facilitating further attacks such as privilege escalation or lateral movement.

## MITRE ATT&CK

- T1018

## Analytic Stories

- Domain Trust Discovery
- IcedID
- NOBELIUM Group
- Graceful Wipe Out Attack
- BlackSuit Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1018/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_adfind_exe.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
