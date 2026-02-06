# Azure AD User Consent Blocked for Risky Application

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects instances where Azure AD has blocked a user's attempt to grant consent to a risky or potentially malicious application. This detection leverages Azure AD audit logs, focusing on user consent actions and system-driven blocks. Monitoring these blocked consent attempts is crucial as it highlights potential threats early on, indicating that a user might be targeted or that malicious applications are attempting to infiltrate the organization. If confirmed malicious, this activity suggests that Azure's security measures successfully prevented a harmful application from accessing organizational data, warranting immediate investigation to understand the context and take preventive measures.

## MITRE ATT&CK

- T1528

## Analytic Stories

- Azure Active Directory Account Takeover

## Data Sources

- Azure Active Directory Consent to application

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1528/azure_ad_user_consent_blocked/azure_ad_user_consent_blocked.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_user_consent_blocked_for_risky_application.yml)*
