# Azure AD Concurrent Sessions From Different Ips

**Type:** TTP

**Author:** Mauricio Velazco, Bhavin Patel, Splunk

## Description

The following analytic detects an Azure AD account with concurrent sessions originating from multiple unique IP addresses within a 5-minute window. It leverages Azure Active Directory NonInteractiveUserSignInLogs to identify this behavior by analyzing successful authentication events and counting distinct source IPs. This activity is significant as it may indicate session hijacking, where an attacker uses stolen session cookies to access corporate resources from a different location. If confirmed malicious, this could lead to unauthorized access to sensitive information and potential data breaches.

## MITRE ATT&CK

- T1185

## Analytic Stories

- Compromised User Account
- Azure Active Directory Account Takeover
- Scattered Lapsus$ Hunters

## Data Sources

- Azure Active Directory

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1185/azure_ad_concurrent_sessions_from_different_ips/azuread.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_concurrent_sessions_from_different_ips.yml)*
