# Azure AD Global Administrator Role Assigned

**Type:** TTP

**Author:** Gowthamaraj Rajendran, Mauricio Velazco, Splunk

## Description

The following analytic detects the assignment of the Azure AD Global Administrator role to a user. It leverages Azure Active Directory AuditLogs to identify when the "Add member to role" operation includes the "Global Administrator" role. This activity is significant because the Global Administrator role grants extensive access to data, resources, and settings, similar to a Domain Administrator in traditional AD environments. If confirmed malicious, this could allow an attacker to establish persistence, escalate privileges, and potentially gain control over Azure resources, posing a severe security risk.

## MITRE ATT&CK

- T1098.003

## Analytic Stories

- Azure Active Directory Persistence
- Azure Active Directory Privilege Escalation
- Scattered Lapsus$ Hunters

## Data Sources

- Azure Active Directory Add member to role

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.003/azure_ad_assign_global_administrator/azure-audit.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_global_administrator_role_assigned.yml)*
