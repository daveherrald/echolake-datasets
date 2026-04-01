# GetAdComputer with PowerShell Script Block

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of the `Get-AdComputer` PowerShell commandlet using PowerShell Script Block Logging (EventCode=4104). This detection leverages script block text to identify when this commandlet is run. The `Get-AdComputer` commandlet is significant as it can be used by adversaries to enumerate all domain computers, aiding in situational awareness and Active Directory discovery. If confirmed malicious, this activity could allow attackers to map the network, identify targets, and plan further attacks, potentially leading to unauthorized access and data exfiltration.

## MITRE ATT&CK

- T1018

## Analytic Stories

- Active Directory Discovery
- CISA AA22-320A
- Medusa Ransomware
- Gozi Malware

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/sbl_xml.log


---

*Source: [Splunk Security Content](detections/endpoint/getadcomputer_with_powershell_script_block.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
