# O365 SharePoint Allowed Domains Policy Changed

**Type:** TTP

**Author:** Steven Dick

## Description

This dataset contains sample data for identifying when the allowed domain settings for O365 SharePoint have been changed. With Azure AD B2B collaboration, users and administrators can invite external users to collaborate with internal users. External guest account invitations may also need access to OneDrive/SharePoint resources. These changed should be monitored by security teams as they could potentially lead to unauthorized access.

## MITRE ATT&CK

- T1136.003

## Analytic Stories

- Azure Active Directory Persistence

## Data Sources

- Office 365 Universal Audit Log

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566/o365_various_alerts/o365_various_alerts.log


---

*Source: [Splunk Security Content](detections/cloud/o365_sharepoint_allowed_domains_policy_changed.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
