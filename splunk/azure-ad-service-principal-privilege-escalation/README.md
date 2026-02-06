# Azure AD Service Principal Privilege Escalation

**Type:** TTP

**Author:** Dean Luxton

## Description

This detection identifies when an Azure Service Principal elevates privileges by adding themself to a new app role assignment.

## MITRE ATT&CK

- T1098.003

## Analytic Stories

- Azure Active Directory Privilege Escalation

## Data Sources

- Azure Active Directory Add app role assignment to service principal

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.003/azure_ad_spn_privesc/azure_ad_spn_privesc.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_service_principal_privilege_escalation.yml)*
