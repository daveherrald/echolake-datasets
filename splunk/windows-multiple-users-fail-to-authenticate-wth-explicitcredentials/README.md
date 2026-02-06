# Windows Multiple Users Fail To Authenticate Wth ExplicitCredentials

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies a source user failing to authenticate with 30 unique users using explicit credentials on a host. It leverages Windows Event 4648, which is generated when a process attempts an account logon by explicitly specifying account credentials. This detection is significant as it may indicate a Password Spraying attack, where an adversary attempts to gain initial access or elevate privileges within an Active Directory environment. If confirmed malicious, this activity could lead to unauthorized access, privilege escalation, and potential compromise of sensitive information.

## MITRE ATT&CK

- T1110.003

## Analytic Stories

- Active Directory Password Spraying
- Insider Threat
- Volt Typhoon

## Data Sources

- Windows Event Log Security 4648

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/purplesharp_explicit_credential_spray_xml/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_multiple_users_fail_to_authenticate_wth_explicitcredentials.yml)*
