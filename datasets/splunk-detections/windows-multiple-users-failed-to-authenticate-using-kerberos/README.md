# Windows Multiple Users Failed To Authenticate Using Kerberos

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying a single source endpoint failing to authenticate with 30 unique users using the Kerberos protocol. It leverages EventCode 4771 with Status 0x18, indicating wrong password attempts, and aggregates these events over a 5-minute window. This behavior is significant as it may indicate a Password Spraying attack, where an adversary attempts to gain initial access or elevate privileges in an Active Directory environment. If confirmed malicious, this activity could lead to unauthorized access, privilege escalation, and potential compromise of sensitive information.

## MITRE ATT&CK

- T1110.003

## Analytic Stories

- Active Directory Password Spraying
- Active Directory Kerberos Attacks
- Volt Typhoon

## Data Sources

- Windows Event Log Security 4771

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/purplesharp_valid_users_kerberos_xml/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_multiple_users_failed_to_authenticate_using_kerberos.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
