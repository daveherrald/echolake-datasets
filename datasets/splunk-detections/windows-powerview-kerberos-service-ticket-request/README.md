# Windows PowerView Kerberos Service Ticket Request

**Type:** TTP

**Author:** Gowthamaraj Rajendran, Splunk

## Description

This dataset contains sample data for detecting the execution of the `Get-DomainSPNTicket` commandlet, part of the PowerView tool, by leveraging PowerShell Script Block Logging (EventCode=4104). This commandlet requests Kerberos service tickets for specified service principal names (SPNs). Monitoring this activity is crucial as it can indicate attempts to perform Kerberoasting, a technique used to extract SPN account passwords via cracking tools like hashcat. If confirmed malicious, this activity could allow attackers to gain unauthorized access to sensitive accounts, potentially leading to privilege escalation and further network compromise.

## MITRE ATT&CK

- T1558.003

## Analytic Stories

- Active Directory Kerberos Attacks
- Rhysida Ransomware

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.003/powerview/windows-powershell-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powerview_kerberos_service_ticket_request.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
