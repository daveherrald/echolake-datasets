# Windows Computer Account With SPN

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the addition of Service Principal Names (SPNs) HOST and RestrictedKrbHost to a computer account, indicative of KrbRelayUp behavior. This detection leverages Windows Security Event Logs, specifically EventCode 4741, to identify changes in SPNs. This activity is significant as it is commonly associated with Kerberos-based attacks, which can be used to escalate privileges or perform lateral movement within a network. If confirmed malicious, this behavior could allow an attacker to impersonate services, potentially leading to unauthorized access to sensitive resources.

## MITRE ATT&CK

- T1558

## Analytic Stories

- Local Privilege Escalation With KrbRelayUp
- Active Directory Kerberos Attacks
- Compromised Windows Host

## Data Sources

- Windows Event Log Security 4741

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558/windows_computer_account_with_spn/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_computer_account_with_spn.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
