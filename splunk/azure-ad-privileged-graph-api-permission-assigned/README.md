# Azure AD Privileged Graph API Permission Assigned

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the assignment of high-risk Graph API permissions in Azure AD, specifically Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All, and RoleManagement.ReadWrite.Directory. It uses azure_monitor_aad data to scan AuditLogs for 'Update application' operations, identifying when these permissions are assigned. This activity is significant as it grants broad control over Azure AD, including application and directory settings. If confirmed malicious, it could lead to unauthorized modifications and potential security breaches, compromising the integrity and security of the Azure AD environment. Immediate investigation is required.

## MITRE ATT&CK

- T1003.002

## Analytic Stories

- Azure Active Directory Persistence
- NOBELIUM Group

## Data Sources

- Azure Active Directory Update application

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.003/azure_ad_privileged_graph_perm_assigned/azure_ad_privileged_graph_perm_assigned.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_privileged_graph_api_permission_assigned.yml)*
