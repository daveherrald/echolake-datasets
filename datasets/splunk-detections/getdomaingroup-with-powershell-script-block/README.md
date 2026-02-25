# GetDomainGroup with PowerShell Script Block

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of the `Get-DomainGroup` cmdlet using PowerShell Script Block Logging (EventCode=4104). This cmdlet, part of the PowerView tool, is used to enumerate domain groups within a Windows domain. The detection leverages script block text to identify this specific command. Monitoring this activity is crucial as it may indicate an adversary or Red Team performing reconnaissance to gain situational awareness and map out Active Directory structures. If confirmed malicious, this activity could lead to further exploitation, including privilege escalation and lateral movement within the network.

## MITRE ATT&CK

- T1069.002

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/domaingroup.log


---

*Source: [Splunk Security Content](detections/endpoint/getdomaingroup_with_powershell_script_block.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
