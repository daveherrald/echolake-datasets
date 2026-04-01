# Azure AD Privileged Authentication Administrator Role Assigned

**Type:** TTP

**Author:** Mauricio Velazco, Gowthamaraj Rajendran, Splunk

## Description

This dataset contains sample data for detecting the assignment of the Privileged Authentication Administrator role to an Azure AD user. It leverages Azure Active Directory audit logs to identify when this specific role is assigned. This activity is significant because users in this role can set or reset authentication methods for any user, including those in privileged roles like Global Administrators. If confirmed malicious, an attacker could change credentials and assume the identity and permissions of high-privilege users, potentially leading to unauthorized access to sensitive information and critical configurations.

## MITRE ATT&CK

- T1003.002

## Analytic Stories

- Azure Active Directory Privilege Escalation
- Scattered Lapsus$ Hunters

## Data Sources

- Azure Active Directory Add member to role

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.003/azure_ad_assign_privileged_role/azure-audit.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_privileged_authentication_administrator_role_assigned.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
