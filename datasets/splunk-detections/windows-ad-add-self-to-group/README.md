# Windows AD add Self to Group

**Type:** TTP

**Author:** Dean Luxton

## Description

This analytic detects instances where a user adds themselves to an Active Directory (AD) group. This activity is a common indicator of privilege escalation, where a user attempts to gain unauthorized access to higher privileges or sensitive resources. By monitoring AD logs, this detection identifies such suspicious behavior, which could be part of a larger attack strategy aimed at compromising critical systems and data.

## MITRE ATT&CK

- T1098

## Analytic Stories

- Sneaky Active Directory Persistence Tricks
- Medusa Ransomware
- Active Directory Privilege Escalation

## Data Sources

- Windows Event Log Security 4728

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/account_manipulation/xml-windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_add_self_to_group.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
