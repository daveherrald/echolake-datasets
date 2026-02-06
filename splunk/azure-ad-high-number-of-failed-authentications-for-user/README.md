# Azure AD High Number Of Failed Authentications For User

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies an Azure AD account experiencing more than 20 failed authentication attempts within a 10-minute window. This detection leverages Azure SignInLogs data, specifically monitoring for error code 50126 and unsuccessful authentication attempts. This behavior is significant as it may indicate a brute force attack targeting the account. If confirmed malicious, an attacker could potentially gain unauthorized access, leading to data breaches or further exploitation within the environment. Security teams should adjust the threshold based on their specific environment to reduce false positives.

## MITRE ATT&CK

- T1110.001

## Analytic Stories

- Compromised User Account
- Azure Active Directory Account Takeover

## Data Sources

- Azure Active Directory

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.001/azure_ad_high_number_of_failed_authentications_for_user/azuread.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_high_number_of_failed_authentications_for_user.yml)*
