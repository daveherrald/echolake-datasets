# Windows AD DCShadow Privileges ACL Addition

**Type:** TTP

**Author:** Dean Luxton

## Description

This detection identifies an Active Directory access-control list (ACL) modification event, which applies the minimum required extended rights to perform the DCShadow attack.

## MITRE ATT&CK

- T1484
- T1207
- T1222.001

## Analytic Stories

- Sneaky Active Directory Persistence Tricks

## Data Sources

- Windows Event Log Security 5136

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1484/DCShadowPermissions/windows-security-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_dcshadow_privileges_acl_addition.yml)*
