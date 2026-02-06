# Windows AD Self DACL Assignment

**Type:** TTP

**Author:** Dean Luxton

## Description

Detect when a user creates a new DACL in AD for their own AD object.

## MITRE ATT&CK

- T1484
- T1098

## Analytic Stories

- Sneaky Active Directory Persistence Tricks

## Data Sources

- Windows Event Log Security 5136

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1484/aclmodification/windows-security-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_self_dacl_assignment.yml)*
