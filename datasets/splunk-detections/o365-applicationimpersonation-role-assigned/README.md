# O365 ApplicationImpersonation Role Assigned

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the assignment of the ApplicationImpersonation role in Office 365 to a user or application. It uses the Office 365 Management Activity API to monitor Azure Active Directory audit logs for role assignment events. This activity is significant because the ApplicationImpersonation role allows impersonation of any user, enabling access to and modification of their mailbox. If confirmed malicious, an attacker could gain unauthorized access to sensitive information, manipulate mailbox data, and perform actions as a legitimate user, posing a severe security risk to the organization.

## MITRE ATT&CK

- T1098.002

## Analytic Stories

- Office 365 Persistence Mechanisms
- Office 365 Collection Techniques
- NOBELIUM Group

## Data Sources

- O365

## Sample Data

- **Source:** O365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.002/application_impersonation_role_assigned/application_impersonation_role_assigned.log


---

*Source: [Splunk Security Content](detections/cloud/o365_applicationimpersonation_role_assigned.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
