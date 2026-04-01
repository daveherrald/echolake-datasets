# Windows Multiple Users Failed To Authenticate From Host Using NTLM

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying a single source endpoint failing to authenticate with 30 unique valid users using the NTLM protocol. It leverages EventCode 4776 from Domain Controller logs, focusing on error code 0xC000006A, which indicates a bad password. This behavior is significant as it may indicate a Password Spraying attack, where an adversary attempts to gain initial access or elevate privileges. If confirmed malicious, this activity could lead to unauthorized access to sensitive information or further compromise of the Active Directory environment.

## MITRE ATT&CK

- T1110.003

## Analytic Stories

- Active Directory Password Spraying
- Volt Typhoon

## Data Sources

- Windows Event Log Security 4776

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/purplesharp_valid_users_ntlm_xml/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_multiple_users_failed_to_authenticate_from_host_using_ntlm.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
