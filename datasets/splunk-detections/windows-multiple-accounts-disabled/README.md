# Windows Multiple Accounts Disabled

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying instances where more than five unique Windows accounts are disabled within a 10-minute window, as indicated by Event Code 4725 in the Windows Security Event Log. It leverages the wineventlog_security dataset, grouping data into 10-minute segments and tracking the count and distinct count of TargetUserName. This behavior is significant as it may indicate internal policy breaches or an external attacker's attempt to disrupt operations. If confirmed malicious, this activity could lead to widespread account lockouts, hindering user access and potentially disrupting business operations.

## MITRE ATT&CK

- T1098
- T1078

## Analytic Stories

- Azure Active Directory Persistence

## Data Sources

- Windows Event Log Security 4725

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/windows_multiple_accounts_disabled/windows_multiple_accounts_disabled.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_multiple_accounts_disabled.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
