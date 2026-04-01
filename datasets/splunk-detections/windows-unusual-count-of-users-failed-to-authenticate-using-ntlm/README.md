# Windows Unusual Count Of Users Failed To Authenticate Using NTLM

**Type:** Anomaly

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying a source endpoint failing to authenticate multiple valid users using the NTLM protocol, potentially indicating a Password Spraying attack. It leverages Event 4776 from Domain Controllers, calculating the standard deviation for each host and applying the 3-sigma rule to detect anomalies. This activity is significant as it may represent an adversary attempting to gain initial access or elevate privileges. If confirmed malicious, the attacker could compromise multiple accounts, leading to unauthorized access and potential lateral movement within the network.

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

*Source: [Splunk Security Content](detections/endpoint/windows_unusual_count_of_users_failed_to_authenticate_using_ntlm.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
