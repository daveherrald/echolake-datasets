# Azure AD Privileged Role Assigned

**Type:** TTP

**Author:** Mauricio Velazco, Gowthamaraj Rajendran, Splunk

## Description

This dataset contains sample data for detecting the assignment of privileged Azure Active Directory roles to a user. It leverages Azure AD audit logs, specifically monitoring the "Add member to role" operation. This activity is significant as adversaries may assign privileged roles to compromised accounts to maintain persistence within the Azure AD environment. If confirmed malicious, this could allow attackers to escalate privileges, access sensitive information, and maintain long-term control over the Azure AD infrastructure.

## MITRE ATT&CK

- T1098.003

## Analytic Stories

- Azure Active Directory Persistence
- NOBELIUM Group
- Scattered Lapsus$ Hunters
- Storm-0501 Ransomware

## Data Sources

- Azure Active Directory Add member to role

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.003/azure_ad_assign_privileged_role/azure-audit.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_privileged_role_assigned.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
