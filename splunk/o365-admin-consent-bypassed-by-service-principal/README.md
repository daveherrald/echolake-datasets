# O365 Admin Consent Bypassed by Service Principal

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies instances where a service principal in Office 365 Azure Active Directory assigns app roles without standard admin consent. It leverages `o365_management_activity` logs, specifically focusing on the 'Add app role assignment to service principal' operation. This activity is significant for SOCs as it may indicate a bypass of critical administrative controls, potentially leading to unauthorized access or privilege escalation. If confirmed malicious, this could allow an attacker to misuse automated processes to assign sensitive permissions, compromising the security of the environment.

## MITRE ATT&CK

- T1098.003

## Analytic Stories

- Office 365 Persistence Mechanisms

## Data Sources

- O365 Add app role assignment to service principal.

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.003/o365_bypass_admin_consent/o365_bypass_admin_consent.log


---

*Source: [Splunk Security Content](detections/cloud/o365_admin_consent_bypassed_by_service_principal.yml)*
