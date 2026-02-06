# Azure AD PIM Role Assignment Activated

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the activation of an Azure AD Privileged Identity Management (PIM) role. It leverages Azure Active Directory events to identify when a user activates a PIM role assignment, indicated by the "Add member to role completed (PIM activation)" operation. Monitoring this activity is crucial as PIM roles grant elevated privileges, and unauthorized activation could indicate an adversary attempting to gain privileged access. If confirmed malicious, this could lead to unauthorized administrative actions, data breaches, or further compromise of the Azure environment.

## MITRE ATT&CK

- T1098.003

## Analytic Stories

- Azure Active Directory Privilege Escalation
- Azure Active Directory Persistence
- Scattered Lapsus$ Hunters

## Data Sources

- Azure Active Directory

## Sample Data

- **Source:** eventhub://researchhub1.servicebus.windows.net/azureadhub;
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.003/azure_ad_pim_role_activated/azure-audit.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_pim_role_assignment_activated.yml)*
