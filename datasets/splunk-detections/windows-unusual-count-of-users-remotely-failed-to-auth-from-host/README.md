# Windows Unusual Count Of Users Remotely Failed To Auth From Host

**Type:** Anomaly

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying a source host failing to authenticate against a remote host with multiple users, potentially indicating a Password Spraying attack. It leverages Windows Event 4625 (failed logon attempts) and Logon Type 3 (remote authentication) to detect this behavior. This activity is significant as it may represent an adversary attempting to gain initial access or elevate privileges within an Active Directory environment. If confirmed malicious, this could lead to unauthorized access, privilege escalation, and further compromise of the network.

## MITRE ATT&CK

- T1110.003

## Analytic Stories

- Active Directory Password Spraying
- Volt Typhoon

## Data Sources

- Windows Event Log Security 4625

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/purplesharp_remote_spray_xml/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_unusual_count_of_users_remotely_failed_to_auth_from_host.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
