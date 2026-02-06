# GetWmiObject DS User with PowerShell

**Type:** TTP

**Author:** Teoderick Contreras, Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of `powershell.exe` with command-line arguments used to query domain users via the `Get-WmiObject` cmdlet and `-class ds_user` parameter. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as it indicates potential reconnaissance efforts by adversaries to enumerate domain users, which is a common step in Active Directory Discovery. If confirmed malicious, this could lead to further attacks, including privilege escalation and lateral movement within the network.

## MITRE ATT&CK

- T1087.002

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/getwmiobject_ds_user_with_powershell.yml)*
