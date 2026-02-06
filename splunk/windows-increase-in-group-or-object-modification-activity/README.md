# Windows Increase in Group or Object Modification Activity

**Type:** TTP

**Author:** Dean Luxton

## Description

This analytic detects an increase in modifications to AD groups or objects. Frequent changes to AD groups or objects can indicate potential security risks, such as unauthorized access attempts, impairing defences or establishing persistence. By monitoring AD logs for unusual modification patterns, this detection helps identify suspicious behavior that could compromise the integrity and security of the AD environment.

## MITRE ATT&CK

- T1098
- T1562

## Analytic Stories

- Sneaky Active Directory Persistence Tricks

## Data Sources

- Windows Event Log Security 4663

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/account_manipulation/xml-windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_increase_in_group_or_object_modification_activity.yml)*
