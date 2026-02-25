# Kerberoasting spn request with RC4 encryption

**Type:** TTP

**Author:** Jose Hernandez, Patrick Bareiss, Mauricio Velazco, Dean Luxton, Splunk

## Description

This dataset contains sample data for detecting potential Kerberoasting attacks by identifying Kerberos service ticket requests with RC4 encryption through Event ID 4769. It leverages specific Ticket_Options values commonly used by Kerberoasting tools. This activity is significant as Kerberoasting allows attackers to request service tickets for domain accounts, typically service accounts, and crack them offline to gain privileged access. If confirmed malicious, this could lead to unauthorized access, privilege escalation, and further compromise of the Active Directory environment.

## MITRE ATT&CK

- T1558.003

## Analytic Stories

- Windows Privilege Escalation
- Data Destruction
- Active Directory Kerberos Attacks
- Compromised Windows Host
- Hermetic Wiper

## Data Sources

- Windows Event Log Security 4769

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.003/kerberoasting_spn_request_with_rc4_encryption/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/kerberoasting_spn_request_with_rc4_encryption.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
