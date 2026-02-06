# Windows Get-AdComputer Unconstrained Delegation Discovery

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the use of the Get-ADComputer cmdlet with parameters indicating a search for Windows endpoints with Kerberos Unconstrained Delegation. It leverages PowerShell Script Block Logging (EventCode=4104) to identify this specific activity. This behavior is significant as it may indicate an attempt by adversaries or Red Teams to gain situational awareness and perform Active Directory discovery. If confirmed malicious, this activity could allow attackers to identify high-value targets for further exploitation, potentially leading to privilege escalation or lateral movement within the network.

## MITRE ATT&CK

- T1018

## Analytic Stories

- Medusa Ransomware
- Active Directory Kerberos Attacks

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1018/windows_get_adcomputer_unconstrained_delegation_discovery/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_get_adcomputer_unconstrained_delegation_discovery.yml)*
