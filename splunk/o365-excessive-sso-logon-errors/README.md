# O365 Excessive SSO logon errors

**Type:** Anomaly

**Author:** Rod Soto, Splunk

## Description

The following analytic detects accounts experiencing a high number of Single Sign-On (SSO) logon errors. It leverages data from the `o365_management_activity` dataset, focusing on failed user login attempts with SSO errors. This activity is significant as it may indicate brute-force attempts or the hijacking/reuse of SSO tokens. If confirmed malicious, attackers could potentially gain unauthorized access to user accounts, leading to data breaches, privilege escalation, or further lateral movement within the organization.

## MITRE ATT&CK

- T1556

## Analytic Stories

- Office 365 Account Takeover
- Cloud Federated Credential Abuse

## Data Sources

- O365 UserLoginFailed

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556/o365_sso_logon_errors/o365_sso_logon_errors2.json


---

*Source: [Splunk Security Content](detections/cloud/o365_excessive_sso_logon_errors.yml)*
