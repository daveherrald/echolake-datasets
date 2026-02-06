# Windows Computer Account Created by Computer Account

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies a computer account creating a new computer account with a specific Service Principal Name (SPN) "RestrictedKrbHost". This detection leverages Windows Security Event Logs, specifically EventCode 4741, to identify such activities. This behavior is significant as it may indicate an attempt to establish unauthorized Kerberos authentication channels, potentially leading to lateral movement or privilege escalation. If confirmed malicious, this activity could allow an attacker to impersonate services, access sensitive information, or maintain persistence within the network.

## MITRE ATT&CK

- T1558

## Analytic Stories

- Active Directory Kerberos Attacks
- Local Privilege Escalation With KrbRelayUp

## Data Sources

- Windows Event Log Security 4741

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558/windows_computer_account_created_by_computer_account/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_computer_account_created_by_computer_account.yml)*
