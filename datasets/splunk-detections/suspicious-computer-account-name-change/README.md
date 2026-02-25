# Suspicious Computer Account Name Change

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting a suspicious computer account name change in Active Directory. It leverages Event ID 4781, which logs account name changes, to identify instances where a computer account name is changed to one that does not end with a `$`. This behavior is significant as it may indicate an attempt to exploit CVE-2021-42278 and CVE-2021-42287, which can lead to domain controller impersonation and privilege escalation. If confirmed malicious, this activity could allow an attacker to gain elevated privileges and potentially control the domain.

## MITRE ATT&CK

- T1078.002

## Analytic Stories

- Active Directory Privilege Escalation
- Compromised Windows Host
- sAMAccountName Spoofing and Domain Controller Impersonation
- Scattered Lapsus$ Hunters

## Data Sources

- Windows Event Log Security 4781

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.002/suspicious_computer_account_name_change/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_computer_account_name_change.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
