# Get WMIObject Group Discovery with Script Block Logging

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of the `Get-WMIObject Win32_Group` command using PowerShell Script Block Logging (EventCode=4104). This method captures the full command sent to PowerShell, allowing for detailed analysis. Identifying group information on an endpoint is not inherently malicious but can be suspicious based on context such as time, endpoint, and user. This activity is significant as it may indicate reconnaissance efforts by an attacker. If confirmed malicious, it could lead to further enumeration and potential lateral movement within the network.

## MITRE ATT&CK

- T1069.001

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.001/atomic_red_team/windows-powershell-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/get_wmiobject_group_discovery_with_script_block_logging.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
