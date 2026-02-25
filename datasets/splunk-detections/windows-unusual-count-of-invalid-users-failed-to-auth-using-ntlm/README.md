# Windows Unusual Count Of Invalid Users Failed To Auth Using NTLM

**Type:** Anomaly

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying a source endpoint failing to authenticate with multiple invalid users using the NTLM protocol. It leverages EventCode 4776 and calculates the standard deviation for each host, using the 3-sigma rule to detect anomalies. This behavior is significant as it may indicate a Password Spraying attack, where an adversary attempts to gain initial access or elevate privileges. If confirmed malicious, this activity could lead to unauthorized access or privilege escalation, posing a significant threat to the Active Directory environment. This detection is focused on domain controllers.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/purplesharp_invalid_users_ntlm_xml/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_unusual_count_of_invalid_users_failed_to_auth_using_ntlm.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
