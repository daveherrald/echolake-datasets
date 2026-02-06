# Azure AD Unusual Number of Failed Authentications From Ip

**Type:** Anomaly

**Author:** Mauricio Velazco, Gowthamaraj Rajendran, Splunk

## Description

The following analytic identifies a single source IP failing to authenticate with multiple valid users, potentially indicating a Password Spraying attack against an Azure Active Directory tenant. It uses Azure SignInLogs data and calculates the standard deviation for source IPs, applying the 3-sigma rule to detect unusual numbers of failed authentication attempts. This activity is significant as it may signal an adversary attempting to gain initial access or elevate privileges. If confirmed malicious, this could lead to unauthorized access, privilege escalation, and potential compromise of sensitive information.

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

*Source: [Splunk Security Content](detections/cloud/azure_ad_unusual_number_of_failed_authentications_from_ip.yml)*
