# O365 Concurrent Sessions From Different Ips

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies user sessions in Office 365 accessed from multiple IP addresses, indicating potential adversary-in-the-middle (AiTM) phishing attacks. It detects this activity by analyzing Azure Active Directory logs for 'UserLoggedIn' operations and flags sessions with more than one associated IP address. This behavior is significant as it suggests unauthorized concurrent access, which is uncommon in normal usage. If confirmed malicious, the impact could include data theft, account takeover, and the launching of internal phishing campaigns, posing severe risks to organizational security.

## MITRE ATT&CK

- T1185

## Analytic Stories

- Office 365 Account Takeover
- Scattered Lapsus$ Hunters

## Data Sources

- O365 UserLoggedIn

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1185/o365_concurrent_sessions_from_different_ips/o365_concurrent_sessions_from_different_ips.log


---

*Source: [Splunk Security Content](detections/cloud/o365_concurrent_sessions_from_different_ips.yml)*
