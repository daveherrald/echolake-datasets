# Azure AD PIM Role Assigned

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the assignment of an Azure AD Privileged Identity Management (PIM) role. It leverages Azure Active Directory events to identify when a user is added as an eligible member to a PIM role. This activity is significant because PIM roles grant elevated privileges, and their assignment should be closely monitored to prevent unauthorized access. If confirmed malicious, an attacker could exploit this to gain privileged access, potentially leading to unauthorized actions, data breaches, or further compromise of the environment.

## MITRE ATT&CK

- T1098.003

## Analytic Stories

- Azure Active Directory Privilege Escalation
- Azure Active Directory Persistence
- Scattered Lapsus$ Hunters

## Data Sources

- Azure Active Directory

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.003/azure_ad_pim_role_activated/azure-audit.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_pim_role_assigned.yml)*
