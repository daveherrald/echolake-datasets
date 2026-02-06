# Suspicious Ticket Granting Ticket Request

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects suspicious Kerberos Ticket Granting Ticket (TGT) requests that may indicate exploitation of CVE-2021-42278 and CVE-2021-42287. It leverages Event ID 4781 (account name change) and Event ID 4768 (TGT request) to identify sequences where a newly renamed computer account requests a TGT. This behavior is significant as it could represent an attempt to escalate privileges by impersonating a Domain Controller. If confirmed malicious, this activity could allow attackers to gain elevated access and potentially control over the domain environment.

## MITRE ATT&CK

- T1078.002

## Analytic Stories

- sAMAccountName Spoofing and Domain Controller Impersonation
- Active Directory Kerberos Attacks
- Active Directory Privilege Escalation

## Data Sources

- Windows Event Log Security 4768
- Windows Event Log Security 4781

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.002/suspicious_ticket_granting_ticket_request/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_ticket_granting_ticket_request.yml)*
