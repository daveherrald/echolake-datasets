# Windows Multiple Disabled Users Failed To Authenticate Wth Kerberos

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects a single source endpoint failing to authenticate with 30 unique disabled domain users using the Kerberos protocol within 5 minutes. It leverages Windows Security Event 4768, focusing on failure code `0x12`, indicating revoked credentials. This activity is significant as it may indicate a Password Spraying attack targeting disabled accounts, a tactic used by adversaries to gain initial access or elevate privileges. If confirmed malicious, this could lead to unauthorized access or privilege escalation within the Active Directory environment, posing a severe security risk.

## MITRE ATT&CK

- T1110.003

## Analytic Stories

- Active Directory Password Spraying
- Active Directory Kerberos Attacks
- Volt Typhoon

## Data Sources

- Windows Event Log Security 4768

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/purplesharp_disabled_users_kerberos_xml/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_multiple_disabled_users_failed_to_authenticate_wth_kerberos.yml)*
