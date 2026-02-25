# Windows AD Privileged Group Modification

**Type:** TTP

**Author:** Dean Luxton

## Description

Detect users added to privileged AD Groups.

## MITRE ATT&CK

- T1098

## Analytic Stories

- Active Directory Privilege Escalation
- Sneaky Active Directory Persistence Tricks

## Data Sources

- Windows Event Log Security 4728

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/account_manipulation/xml-windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_privileged_group_modification.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
