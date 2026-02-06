# Azure AD Application Administrator Role Assigned

**Type:** TTP

**Author:** Mauricio Velazco, Gowthamaraj Rajendran, Splunk

## Description

The following analytic identifies the assignment of the Application Administrator role to an Azure AD user. It leverages Azure Active Directory events, specifically monitoring the "Add member to role" operation. This activity is significant because users in this role can manage all aspects of enterprise applications, including credentials, which can be used to impersonate application identities. If confirmed malicious, an attacker could escalate privileges, manage application settings, and potentially access sensitive resources by impersonating application identities, posing a significant security risk to the Azure AD tenant.

## MITRE ATT&CK

- T1098.003

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

*Source: [Splunk Security Content](detections/cloud/azure_ad_application_administrator_role_assigned.yml)*
