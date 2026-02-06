# Detect Password Spray Attempts

**Type:** TTP

**Author:** Dean Luxton

## Description

This analytic employs the 3-sigma approach to detect an unusual volume of failed authentication attempts from a single source. A password spray attack is a type of brute force attack where an attacker tries a few common passwords across many different accounts to avoid detection and account lockouts. By utilizing the Authentication Data Model, this detection is effective for all CIM-mapped authentication events, providing comprehensive coverage and enhancing security against these attacks.

## MITRE ATT&CK

- T1110.003

## Analytic Stories

- Compromised User Account
- Active Directory Password Spraying

## Data Sources

- Windows Event Log Security 4625

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/purplesharp_invalid_users_kerberos_xml/windows-security.log


---

*Source: [Splunk Security Content](detections/application/detect_password_spray_attempts.yml)*
