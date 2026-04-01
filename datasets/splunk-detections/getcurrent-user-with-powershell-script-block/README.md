# GetCurrent User with PowerShell Script Block

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of the `GetCurrent` method from the WindowsIdentity .NET class using PowerShell Script Block Logging (EventCode=4104). This method identifies the current Windows user. The detection leverages PowerShell script block logs to identify when this method is called. This activity is significant because adversaries and Red Teams may use it to gain situational awareness and perform Active Directory discovery on compromised endpoints. If confirmed malicious, this could allow attackers to map out user accounts and potentially escalate privileges or move laterally within the network.

## MITRE ATT&CK

- T1033

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1033/AD_discovery/windows-powershell-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/getcurrent_user_with_powershell_script_block.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
