# Windows PowerView Unconstrained Delegation Discovery

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the use of PowerView commandlets to discover Windows endpoints with Kerberos Unconstrained Delegation. It leverages PowerShell Script Block Logging (EventCode=4104) to identify specific commands like `Get-DomainComputer` or `Get-NetComputer` with the `-Unconstrained` parameter. This activity is significant as it indicates potential reconnaissance efforts by adversaries or Red Teams to map out privileged delegation settings in Active Directory. If confirmed malicious, this could allow attackers to identify high-value targets for further exploitation, potentially leading to privilege escalation or lateral movement within the network.

## MITRE ATT&CK

- T1018

## Analytic Stories

- CISA AA23-347A
- Rhysida Ransomware
- Active Directory Kerberos Attacks

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1018/windows_powerview_constrained_delegation_discovery/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powerview_unconstrained_delegation_discovery.yml)*
