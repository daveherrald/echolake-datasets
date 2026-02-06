# Windows Computer Account Requesting Kerberos Ticket

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects a computer account requesting a Kerberos ticket, which is unusual as typically user accounts request these tickets. This detection leverages Windows Security Event Logs, specifically EventCode 4768, to identify instances where the TargetUserName ends with a dollar sign ($), indicating a computer account. This activity is significant because it may indicate the use of tools like KrbUpRelay or other Kerberos-based attacks. If confirmed malicious, this could allow attackers to impersonate computer accounts, potentially leading to unauthorized access and lateral movement within the network.

## MITRE ATT&CK

- T1558

## Analytic Stories

- Active Directory Kerberos Attacks
- Local Privilege Escalation With KrbRelayUp

## Data Sources

- Windows Event Log Security 4768

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558/windows_computer_account_requesting_kerberos_ticket/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_computer_account_requesting_kerberos_ticket.yml)*
