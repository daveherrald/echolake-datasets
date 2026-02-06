# Azure AD Multiple Users Failing To Authenticate From Ip

**Type:** Anomaly

**Author:** Mauricio Velazco, Gowthamaraj Rajendran, Splunk

## Description

The following analytic detects a single source IP failing to authenticate with 30 unique valid users within 5 minutes in Azure Active Directory. It leverages Azure AD SignInLogs with error code 50126, indicating invalid passwords. This behavior is significant as it may indicate a Password Spraying attack, where an adversary attempts to gain initial access or elevate privileges by trying common passwords across many accounts. If confirmed malicious, this activity could lead to unauthorized access, data breaches, or privilege escalation within the Azure AD environment.

## MITRE ATT&CK

- T1110.003
- T1110.004
- T1586.003

## Analytic Stories

- Azure Active Directory Account Takeover

## Data Sources

- Azure Active Directory

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/password_spraying_azuread/azuread_signin.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_multiple_users_failing_to_authenticate_from_ip.yml)*
