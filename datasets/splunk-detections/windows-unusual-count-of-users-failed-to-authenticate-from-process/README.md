# Windows Unusual Count Of Users Failed To Authenticate From Process

**Type:** Anomaly

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying a source process failing to authenticate multiple users, potentially indicating a Password Spraying attack. It leverages Windows Event 4625, which logs failed logon attempts, and uses statistical analysis to detect anomalies. This activity is significant as it may represent an adversary attempting to gain initial access or elevate privileges within an Active Directory environment. If confirmed malicious, the attacker could compromise multiple accounts, leading to unauthorized access, data exfiltration, or further lateral movement within the network.

## MITRE ATT&CK

- T1110.003

## Analytic Stories

- Active Directory Password Spraying
- Insider Threat
- Volt Typhoon

## Data Sources

- Windows Event Log Security 4625

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/purplesharp_multiple_users_from_process_xml/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_unusual_count_of_users_failed_to_authenticate_from_process.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
