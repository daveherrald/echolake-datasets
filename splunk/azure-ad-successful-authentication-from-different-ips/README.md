# Azure AD Successful Authentication From Different Ips

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects an Azure AD account successfully authenticating from multiple unique IP addresses within a 30-minute window. It leverages Azure AD SignInLogs to identify instances where the same user logs in from different IPs in a short time frame. This behavior is significant as it may indicate compromised credentials being used by an adversary, potentially following a phishing attack. If confirmed malicious, this activity could allow unauthorized access to corporate resources, leading to data breaches or further exploitation within the network.

## MITRE ATT&CK

- T1110.001
- T1110.003

## Analytic Stories

- Compromised User Account
- Azure Active Directory Account Takeover

## Data Sources

- Azure Active Directory

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.001/azure_ad_successful_authentication_from_different_ips/azuread.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_successful_authentication_from_different_ips.yml)*
