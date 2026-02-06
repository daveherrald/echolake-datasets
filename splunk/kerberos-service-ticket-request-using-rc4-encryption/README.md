# Kerberos Service Ticket Request Using RC4 Encryption

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects Kerberos service ticket requests using RC4 encryption, leveraging Kerberos Event 4769. This method identifies potential Golden Ticket attacks, where adversaries forge Kerberos Granting Tickets (TGT) using the Krbtgt account NTLM password hash to gain unrestricted access to an Active Directory environment. Monitoring for RC4 encryption usage is significant as it is rare in modern networks, indicating possible malicious activity. If confirmed malicious, attackers could move laterally and execute code on remote systems, compromising the entire network. Note: This detection may be bypassed if attackers use the AES key instead of the NTLM hash.

## MITRE ATT&CK

- T1558.001

## Analytic Stories

- Active Directory Kerberos Attacks
- Active Directory Privilege Escalation
- Scattered Lapsus$ Hunters

## Data Sources

- Windows Event Log Security 4769

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.001/kerberos_service_ticket_request_using_rc4_encryption/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/kerberos_service_ticket_request_using_rc4_encryption.yml)*
