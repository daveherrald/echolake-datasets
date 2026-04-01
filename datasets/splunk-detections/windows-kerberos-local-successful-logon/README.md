# Windows Kerberos Local Successful Logon

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying a local successful authentication event on a Windows endpoint using the Kerberos package. It detects EventCode 4624 with LogonType 3 and source address 127.0.0.1, indicating a login to the built-in local Administrator account. This activity is significant as it may suggest a Kerberos relay attack, a method attackers use to escalate privileges. If confirmed malicious, this could allow an attacker to gain unauthorized access to sensitive systems, execute arbitrary code, or create new accounts in Active Directory, leading to potential system compromise.

## MITRE ATT&CK

- T1558

## Analytic Stories

- Local Privilege Escalation With KrbRelayUp
- Active Directory Kerberos Attacks
- Compromised Windows Host
- Scattered Lapsus$ Hunters

## Data Sources

- Windows Event Log Security 4624

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558/windows_kerberos_local_successful_logon/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_kerberos_local_successful_logon.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
