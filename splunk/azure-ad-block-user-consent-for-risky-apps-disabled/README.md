# Azure AD Block User Consent For Risky Apps Disabled

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects when the risk-based step-up consent security setting in Azure AD is disabled. It monitors Azure Active Directory logs for the "Update authorization policy" operation, specifically changes to the "AllowUserConsentForRiskyApps" setting. This activity is significant because disabling this feature can expose the organization to OAuth phishing threats by allowing users to grant consent to potentially malicious applications. If confirmed malicious, attackers could gain unauthorized access to user data and sensitive information, leading to data breaches and further compromise within the organization.

## MITRE ATT&CK

- T1562

## Analytic Stories

- Azure Active Directory Account Takeover

## Data Sources

- Azure Active Directory Update authorization policy

## Sample Data

- **Source:** Azure Ad
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562/azuread_disable_blockconsent_for_riskapps/azuread_disable_blockconsent_for_riskapps.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_block_user_consent_for_risky_apps_disabled.yml)*
