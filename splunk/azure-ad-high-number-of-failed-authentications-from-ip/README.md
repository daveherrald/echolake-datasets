# Azure AD High Number Of Failed Authentications From Ip

**Type:** TTP

**Author:** Mauricio Velazco, Bhavin Patel, Splunk

## Description

The following analytic detects an IP address with 20 or more failed authentication attempts to an Azure AD tenant within 10 minutes. It leverages Azure AD SignInLogs to identify repeated failed logins from the same IP. This behavior is significant as it may indicate a brute force attack aimed at gaining unauthorized access or escalating privileges. If confirmed malicious, the attacker could potentially compromise user accounts, leading to unauthorized access to sensitive information and resources within the Azure environment.

## MITRE ATT&CK

- T1110.001
- T1110.003

## Analytic Stories

- Compromised User Account
- Azure Active Directory Account Takeover
- NOBELIUM Group

## Data Sources

- Azure Active Directory

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.001/azure_ad_high_number_of_failed_authentications_for_user/azuread.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_high_number_of_failed_authentications_from_ip.yml)*
