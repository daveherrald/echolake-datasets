# Windows Multiple Users Remotely Failed To Authenticate From Host

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying a source host failing to authenticate against a remote host with 30 unique users. It leverages Windows Event 4625 with Logon Type 3, indicating remote authentication attempts. This behavior is significant as it may indicate a Password Spraying attack, where an adversary attempts to gain initial access or elevate privileges in an Active Directory environment. If confirmed malicious, this activity could lead to unauthorized access, privilege escalation, and potential compromise of sensitive information. This detection is crucial for real-time security monitoring and threat hunting.

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

*Source: [Splunk Security Content](detections/endpoint/windows_multiple_users_remotely_failed_to_authenticate_from_host.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
