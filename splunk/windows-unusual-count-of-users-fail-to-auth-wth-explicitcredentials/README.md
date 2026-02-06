# Windows Unusual Count Of Users Fail To Auth Wth ExplicitCredentials

**Type:** Anomaly

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies a source user failing to authenticate with multiple users using explicit credentials on a host. It leverages Windows Event Code 4648 and calculates the standard deviation for each host, using the 3-sigma rule to detect anomalies. This behavior is significant as it may indicate a Password Spraying attack, where an adversary attempts to gain initial access or elevate privileges. If confirmed malicious, this activity could lead to unauthorized access, privilege escalation, or further compromise of the Active Directory environment.

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

*Source: [Splunk Security Content](detections/endpoint/windows_unusual_count_of_users_fail_to_auth_wth_explicitcredentials.yml)*
