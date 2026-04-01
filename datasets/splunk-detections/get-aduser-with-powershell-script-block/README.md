# Get ADUser with PowerShell Script Block

**Type:** Hunting

**Author:** Teoderick Contreras, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of the `Get-AdUser` PowerShell cmdlet, which is used to enumerate all domain users. It leverages PowerShell Script Block Logging (EventCode=4104) to identify instances where this command is executed with a filter. This activity is significant as it may indicate an attempt by adversaries or Red Teams to gather information about domain users for situational awareness and Active Directory discovery. If confirmed malicious, this behavior could lead to further reconnaissance and potential exploitation of user accounts within the domain.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/AD_discovery/aduser_powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/get_aduser_with_powershell_script_block.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
