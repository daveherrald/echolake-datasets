# Windows Unusual Count Of Disabled Users Failed Auth Using Kerberos

**Type:** Anomaly

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying a source endpoint failing to authenticate with multiple disabled domain users using the Kerberos protocol. It leverages EventCode 4768, which is generated when the Key Distribution Center issues a Kerberos Ticket Granting Ticket (TGT) and detects failure code `0x12` (credentials revoked). This behavior is significant as it may indicate a Password Spraying attack targeting disabled accounts, potentially leading to initial access or privilege escalation. If confirmed malicious, attackers could gain unauthorized access or elevate privileges within the Active Directory environment.

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

*Source: [Splunk Security Content](detections/endpoint/windows_unusual_count_of_disabled_users_failed_auth_using_kerberos.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
