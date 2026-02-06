# Azure AD FullAccessAsApp Permission Assigned

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the assignment of the 'full_access_as_app' permission to an application within Office 365 Exchange Online. This is identified by the GUID 'dc890d15-9560-4a4c-9b7f-a736ec74ec40' and the ResourceAppId '00000002-0000-0ff1-ce00-000000000000'. The detection leverages the azure_monitor_aad data source, focusing on AuditLogs with the operation name 'Update application'. This activity is significant as it grants broad control over Office 365 operations, including full access to all mailboxes and the ability to send emails as any user. If malicious, this could lead to unauthorized access and data exfiltration.

## MITRE ATT&CK

- T1098.002
- T1098.003

## Analytic Stories

- Azure Active Directory Persistence
- NOBELIUM Group

## Data Sources

- Azure Active Directory Update application

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.002/full_access_as_app_permission_assigned/full_access_as_app_permission_assigned.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_fullaccessasapp_permission_assigned.yml)*
