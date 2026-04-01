# GetDomainGroup with PowerShell

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of `powershell.exe` with command-line arguments that query for domain groups using `Get-DomainGroup`. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions mapped to the `Processes` node of the `Endpoint` data model. Monitoring this activity is crucial as `Get-DomainGroup` is part of PowerView, a tool often used by adversaries for domain enumeration and situational awareness. If confirmed malicious, this activity could allow attackers to gain insights into domain group structures, aiding in further exploitation and privilege escalation.

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

*Source: [Splunk Security Content](detections/endpoint/getdomaingroup_with_powershell.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
