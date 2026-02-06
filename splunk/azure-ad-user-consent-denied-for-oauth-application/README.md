# Azure AD User Consent Denied for OAuth Application

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies instances where a user has denied consent to an OAuth application seeking permissions within the Azure AD environment. This detection leverages Azure AD's audit logs, specifically focusing on user consent actions with error code 65004. Monitoring denied consent actions is significant as it can indicate users recognizing potentially suspicious or untrusted applications. If confirmed malicious, this activity could suggest attempts by unauthorized applications to gain access, potentially leading to data breaches or unauthorized actions within the environment. Understanding these denials helps refine security policies and enhance user awareness.

## MITRE ATT&CK

- T1528

## Analytic Stories

- Azure Active Directory Account Takeover

## Data Sources

- Azure Active Directory Sign-in activity

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1528/azure_ad_user_consent_declined/azure_ad_user_consent_declined.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_user_consent_denied_for_oauth_application.yml)*
