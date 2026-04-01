# Get DomainUser with PowerShell Script Block

**Type:** TTP

**Author:** Teoderick Contreras, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of the `Get-DomainUser` cmdlet using PowerShell Script Block Logging (EventCode=4104). This cmdlet is part of PowerView, a tool often used for domain enumeration. The detection leverages PowerShell operational logs to identify instances where this command is executed. Monitoring this activity is crucial as it may indicate an adversary's attempt to gather information about domain users, which is a common step in Active Directory Discovery. If confirmed malicious, this activity could lead to further reconnaissance and potential exploitation of domain resources.

## MITRE ATT&CK

- T1087.002

## Analytic Stories

- Active Directory Discovery
- CISA AA23-347A

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/AD_discovery/windows-powershell-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/get_domainuser_with_powershell_script_block.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
