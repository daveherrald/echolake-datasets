# Windows Unusual Count Of Users Failed To Auth Using Kerberos

**Type:** Anomaly

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies a source endpoint failing to authenticate multiple valid users using the Kerberos protocol, potentially indicating a Password Spraying attack. It leverages Event 4771, which is generated when the Key Distribution Center fails to issue a Kerberos Ticket Granting Ticket (TGT) due to a wrong password (failure code 0x18). This detection uses statistical analysis, specifically the 3-sigma rule, to identify unusual authentication failures. If confirmed malicious, this activity could allow an attacker to gain initial access or elevate privileges within an Active Directory environment.

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

*Source: [Splunk Security Content](detections/endpoint/windows_unusual_count_of_users_failed_to_auth_using_kerberos.yml)*
