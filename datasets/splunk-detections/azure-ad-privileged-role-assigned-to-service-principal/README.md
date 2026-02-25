# Azure AD Privileged Role Assigned to Service Principal

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the assignment of privileged roles to service principals in Azure Active Directory (AD). It leverages the AuditLogs log category from ingested Azure AD events. This activity is significant because assigning elevated permissions to non-human entities can lead to unauthorized access or malicious activities. If confirmed malicious, attackers could exploit these service principals to gain elevated access to Azure resources, potentially compromising sensitive data and critical infrastructure. Monitoring this behavior helps prevent privilege escalation and ensures the security of Azure environments.

## MITRE ATT&CK

- T1098.003

## Analytic Stories

- Azure Active Directory Privilege Escalation
- NOBELIUM Group
- Scattered Lapsus$ Hunters

## Data Sources

- Azure Active Directory Add member to role

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.003/azure_ad_privileged_role_serviceprincipal/azure-audit.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_privileged_role_assigned_to_service_principal.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
