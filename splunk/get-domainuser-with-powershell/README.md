# Get DomainUser with PowerShell

**Type:** TTP

**Author:** Teoderick Contreras, Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of `powershell.exe` with command-line arguments used to enumerate domain users via the `Get-DomainUser` command. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions mapped to the `Processes` node of the `Endpoint` data model. This activity is significant as it indicates potential reconnaissance efforts by adversaries or Red Teams using PowerView for Active Directory discovery. If confirmed malicious, this could allow attackers to gain situational awareness and identify valuable targets within the domain, potentially leading to further exploitation.

## MITRE ATT&CK

- T1087.002

## Analytic Stories

- Active Directory Discovery
- CISA AA23-347A

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/get_domainuser_with_powershell.yml)*
