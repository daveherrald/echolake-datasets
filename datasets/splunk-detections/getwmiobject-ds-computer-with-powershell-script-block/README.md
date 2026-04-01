# GetWmiObject Ds Computer with PowerShell Script Block

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of the `Get-WmiObject` cmdlet with the `DS_Computer` class parameter via PowerShell Script Block Logging (EventCode=4104). This detection leverages script block text to identify queries targeting domain computers using WMI. Monitoring this activity is crucial as adversaries and Red Teams may use it for Active Directory Discovery and situational awareness. If confirmed malicious, this behavior could allow attackers to map out domain computers, facilitating further attacks such as lateral movement or privilege escalation.

## MITRE ATT&CK

- T1018

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/sbl_xml.log


---

*Source: [Splunk Security Content](detections/endpoint/getwmiobject_ds_computer_with_powershell_script_block.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
