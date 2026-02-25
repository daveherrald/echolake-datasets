# Windows Multiple Accounts Deleted

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the deletion of more than five unique Windows accounts within a 10-minute period, using Event Code 4726 from the Windows Security Event Log. It leverages the `wineventlog_security` dataset, segmenting data into 10-minute intervals to identify suspicious account deletions. This activity is significant as it may indicate an attacker attempting to erase traces of their actions. If confirmed malicious, this could lead to unauthorized access removal, hindering incident response and forensic investigations.

## MITRE ATT&CK

- T1098
- T1078

## Analytic Stories

- Azure Active Directory Persistence

## Data Sources

- Windows Event Log Security 4726

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/windows_multiple_accounts_deleted/windows_multiple_accounts_deleted.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_multiple_accounts_deleted.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
