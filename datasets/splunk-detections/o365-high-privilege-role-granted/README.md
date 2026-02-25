# O365 High Privilege Role Granted

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting when high-privilege roles such as "Exchange Administrator," "SharePoint Administrator," or "Global Administrator" are granted within Office 365. It leverages O365 audit logs to identify events where these roles are assigned to any user or service account. This activity is significant for SOCs as these roles provide extensive permissions, allowing broad access and control over critical resources and data. If confirmed malicious, this could enable attackers to gain significant control over O365 resources, access, modify, or delete critical data, and compromise the overall security and functionality of the O365 environment.

## MITRE ATT&CK

- T1098.003

## Analytic Stories

- Office 365 Persistence Mechanisms

## Data Sources

- O365 Add member to role.

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.003/o365_high_priv_role_assigned/o365_high_priv_role_assigned.log


---

*Source: [Splunk Security Content](detections/cloud/o365_high_privilege_role_granted.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
