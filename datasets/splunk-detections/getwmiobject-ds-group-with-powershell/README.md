# GetWmiObject Ds Group with PowerShell

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying the execution of `powershell.exe` with command-line arguments used to query domain groups via the `Get-WmiObject` cmdlet and the `-class ds_group` parameter. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as it indicates potential reconnaissance efforts by adversaries to enumerate domain groups, which is a common step in Active Directory Discovery. If confirmed malicious, this could allow attackers to gain insights into the domain structure, aiding in further attacks and privilege escalation.

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

*Source: [Splunk Security Content](detections/endpoint/getwmiobject_ds_group_with_powershell.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
