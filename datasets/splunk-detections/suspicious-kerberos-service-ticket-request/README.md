# Suspicious Kerberos Service Ticket Request

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting suspicious Kerberos Service Ticket (TGS) requests where the requesting account name matches the service name, potentially indicating an exploitation attempt of CVE-2021-42278 and CVE-2021-42287. This detection leverages Event ID 4769 from Domain Controller and Kerberos events. Such activity is significant as it may represent an adversary attempting to escalate privileges by impersonating a domain controller. If confirmed malicious, this could allow an attacker to take control of the domain controller, leading to complete domain compromise and unauthorized access to sensitive information.

## MITRE ATT&CK

- T1078.002

## Analytic Stories

- sAMAccountName Spoofing and Domain Controller Impersonation
- Active Directory Kerberos Attacks
- Active Directory Privilege Escalation

## Data Sources

- Windows Event Log Security 4769

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.001/suspicious_kerberos_service_ticket_request/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_kerberos_service_ticket_request.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
