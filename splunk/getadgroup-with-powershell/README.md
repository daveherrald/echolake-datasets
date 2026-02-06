# GetAdGroup with PowerShell

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of `powershell.exe` with the `Get-AdGroup` commandlet, which is used to query domain groups in a Windows Domain. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. Monitoring this activity is crucial as it may indicate an adversary or Red Team enumerating domain groups for situational awareness and Active Directory discovery. If confirmed malicious, this activity could lead to further reconnaissance, privilege escalation, or lateral movement within the network.

## MITRE ATT&CK

- T1069.002

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.002/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/getadgroup_with_powershell.yml)*
