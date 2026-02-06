# O365 Privileged Graph API Permission Assigned

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the assignment of critical Graph API permissions in Azure AD using the O365 Unified Audit Log. It focuses on permissions such as Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All, and RoleManagement.ReadWrite.Directory. The detection method leverages Azure Active Directory workload events, specifically 'Update application' operations. This activity is significant as these permissions provide extensive control over Azure AD settings, posing a high risk if misused. If confirmed malicious, this could allow unauthorized modifications, leading to potential data breaches or privilege escalation. Immediate investigation is crucial.

## MITRE ATT&CK

- T1003.002

## Analytic Stories

- Office 365 Persistence Mechanisms
- NOBELIUM Group

## Data Sources

- O365 Update application.

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.003/o365_privileged_graph_perm_assigned/o365_privileged_graph_perm_assigned.log


---

*Source: [Splunk Security Content](detections/cloud/o365_privileged_graph_api_permission_assigned.yml)*
