# Windows AD Replication Request Initiated by User Account

**Type:** TTP

**Author:** Dean Luxton

## Description

This dataset contains sample data for detecting a user account initiating an Active Directory replication request, indicative of a DCSync attack. It leverages EventCode 4662 from the Windows Security Event Log, focusing on specific object types and replication permissions. This activity is significant because it can allow an attacker with sufficient privileges to request password hashes for any or all users within the domain. If confirmed malicious, this could lead to unauthorized access, privilege escalation, and potential compromise of the entire domain.

## MITRE ATT&CK

- T1003.006

## Analytic Stories

- Compromised Windows Host
- Sneaky Active Directory Persistence Tricks
- Credential Dumping

## Data Sources

- Windows Event Log Security 4662
- Windows Event Log Security 4624

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.006/mimikatz/xml-windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_replication_request_initiated_by_user_account.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
