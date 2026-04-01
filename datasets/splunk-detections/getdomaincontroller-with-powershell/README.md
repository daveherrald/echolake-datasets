# GetDomainController with PowerShell

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of `powershell.exe` with the `Get-DomainController` command, which is used to discover remote systems within a Windows domain. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. Monitoring this activity is crucial as it may indicate an attempt to enumerate domain controllers, a common tactic in Active Directory discovery. If confirmed malicious, this activity could allow attackers to gain situational awareness, potentially leading to further exploitation and lateral movement within the network.

## MITRE ATT&CK

- T1018

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1018/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/getdomaincontroller_with_powershell.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
