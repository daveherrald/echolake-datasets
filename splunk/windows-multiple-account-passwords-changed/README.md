# Windows Multiple Account Passwords Changed

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects instances where more than five unique Windows account passwords are changed within a 10-minute interval. It leverages Event Code 4724 from the Windows Security Event Log, using the wineventlog_security dataset to monitor and count distinct TargetUserName values. This behavior is significant as rapid password changes across multiple accounts are unusual and may indicate unauthorized access or internal compromise. If confirmed malicious, this activity could lead to widespread account compromise, unauthorized access to sensitive information, and potential disruption of services.

## MITRE ATT&CK

- T1098
- T1078

## Analytic Stories

- Azure Active Directory Persistence

## Data Sources

- Windows Event Log Security 4724

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/windows_multiple_passwords_changed/windows_multiple_passwords_changed.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_multiple_account_passwords_changed.yml)*
