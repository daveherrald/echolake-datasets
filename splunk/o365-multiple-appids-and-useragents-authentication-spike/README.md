# O365 Multiple AppIDs and UserAgents Authentication Spike

**Type:** Anomaly

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies unusual authentication activity in an O365 environment, where a single user account experiences more than 8 authentication attempts using 3 or more unique application IDs and over 5 unique user agents within a short timeframe. It leverages O365 audit logs, focusing on authentication events and applying statistical thresholds. This behavior is significant as it may indicate an adversary probing for multi-factor authentication weaknesses. If confirmed malicious, it suggests a compromised account, potentially leading to unauthorized access, privilege escalation, and data exfiltration. Early detection is crucial to prevent further exploitation.

## MITRE ATT&CK

- T1078

## Analytic Stories

- Office 365 Account Takeover

## Data Sources

- O365 UserLoggedIn
- O365 UserLoginFailed

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/o365_multiple_appids_and_useragents_auth/o365_multiple_appids_and_useragents_auth.log


---

*Source: [Splunk Security Content](detections/cloud/o365_multiple_appids_and_useragents_authentication_spike.yml)*
