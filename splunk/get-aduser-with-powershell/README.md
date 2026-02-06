# Get ADUser with PowerShell

**Type:** Hunting

**Author:** Teoderick Contreras, Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of `powershell.exe` with command-line arguments used to enumerate domain users via the `Get-ADUser` cmdlet. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as it may indicate an attempt by adversaries to gather information about domain users for situational awareness and Active Directory discovery. If confirmed malicious, this behavior could lead to further reconnaissance, enabling attackers to identify high-value targets and plan subsequent attacks.

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

*Source: [Splunk Security Content](detections/endpoint/get_aduser_with_powershell.yml)*
