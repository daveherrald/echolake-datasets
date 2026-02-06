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
