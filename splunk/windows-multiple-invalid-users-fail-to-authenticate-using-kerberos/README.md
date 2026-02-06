# Windows Multiple Invalid Users Fail To Authenticate Using Kerberos

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies a source endpoint failing to authenticate with 30 unique invalid domain users using the Kerberos protocol. This detection leverages EventCode 4768, specifically looking for failure code 0x6, indicating the user is not found in the Kerberos database. This activity is significant as it may indicate a Password Spraying attack, where an adversary attempts to gain initial access or elevate privileges. If confirmed malicious, this could lead to unauthorized access or privilege escalation within the Active Directory environment, posing a significant security risk.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/purplesharp_invalid_users_kerberos_xml/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_multiple_invalid_users_fail_to_authenticate_using_kerberos.yml)*
