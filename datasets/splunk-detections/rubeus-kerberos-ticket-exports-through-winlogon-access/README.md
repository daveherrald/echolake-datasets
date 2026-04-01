# Rubeus Kerberos Ticket Exports Through Winlogon Access

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting a process accessing the winlogon.exe system process, indicative of the Rubeus tool attempting to export Kerberos tickets from memory. This detection leverages Sysmon EventCode 10 logs, focusing on processes obtaining a handle to winlogon.exe with specific access rights. This activity is significant as it often precedes pass-the-ticket attacks, where adversaries use stolen Kerberos tickets to move laterally within an environment. If confirmed malicious, this could allow attackers to bypass normal access controls, escalate privileges, and persist within the network, posing a severe security risk.

## MITRE ATT&CK

- T1550.003

## Analytic Stories

- CISA AA23-347A
- Active Directory Kerberos Attacks
- BlackSuit Ransomware
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 10

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1550.003/rubeus/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/rubeus_kerberos_ticket_exports_through_winlogon_access.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
