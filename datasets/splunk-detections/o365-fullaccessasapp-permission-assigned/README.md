# O365 FullAccessAsApp Permission Assigned

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the assignment of the 'full_access_as_app' permission to an application registration in Office 365 Exchange Online. This detection leverages Office 365 management activity logs and filters Azure Active Directory workload events to identify when the specific permission, identified by GUID 'dc890d15-9560-4a4c-9b7f-a736ec74ec40', is granted. This activity is significant because it provides extensive control over Office 365 operations, including access to all mailboxes and the ability to send mail as any user. If confirmed malicious, this could lead to unauthorized data access, exfiltration, or account compromise. Immediate investigation is required.

## MITRE ATT&CK

- T1098.002
- T1098.003

## Analytic Stories

- Office 365 Persistence Mechanisms
- NOBELIUM Group

## Data Sources

- O365 Update application.

## Sample Data

- **Source:** o365:management:activity
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.002/o365_full_access_as_app_permission_assigned/o365_full_access_as_app_permission_assigned.log


---

*Source: [Splunk Security Content](detections/cloud/o365_fullaccessasapp_permission_assigned.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
