# Azure AD Multiple AppIDs and UserAgents Authentication Spike

**Type:** Anomaly

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects unusual authentication activity in Azure AD, specifically when a single user account has over 8 authentication attempts using 3+ unique application IDs and 5+ unique user agents within a short period. It leverages Azure AD audit logs, focusing on authentication events and using statistical thresholds. This behavior is significant as it may indicate an adversary probing for MFA requirements. If confirmed malicious, it suggests a compromised account, potentially leading to further exploitation, lateral movement, and data exfiltration. Early detection is crucial to prevent substantial harm.

## MITRE ATT&CK

- T1078

## Analytic Stories

- Azure Active Directory Account Takeover

## Data Sources

- Azure Active Directory Sign-in activity

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/azure_ad_multiple_appids_and_useragents_auth/azure_ad_multiple_appids_and_useragents_auth.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_multiple_appids_and_useragents_authentication_spike.yml)*
