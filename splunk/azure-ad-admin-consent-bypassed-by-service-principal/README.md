# Azure AD Admin Consent Bypassed by Service Principal

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies instances where a service principal in Azure Active Directory assigns app roles without standard admin consent. It uses Entra ID logs from the `azure_monitor_aad` data source, focusing on the "Add app role assignment to service principal" operation. This detection is significant as it highlights potential bypasses of critical administrative consent processes, which could lead to unauthorized privileges being granted. If confirmed malicious, this activity could allow attackers to exploit automation to assign sensitive permissions without proper oversight, potentially compromising the security of the Azure AD environment.

## MITRE ATT&CK

- T1098.003

## Analytic Stories

- Azure Active Directory Privilege Escalation
- NOBELIUM Group

## Data Sources

- Azure Active Directory Add app role assignment to service principal

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.003/azure_ad_bypass_admin_consent/azure_ad_bypass_admin_consent.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_admin_consent_bypassed_by_service_principal.yml)*
