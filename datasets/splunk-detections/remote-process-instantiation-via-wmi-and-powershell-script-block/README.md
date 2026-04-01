# Remote Process Instantiation via WMI and PowerShell Script Block

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of the `Invoke-WmiMethod` commandlet with parameters used to start a process on a remote endpoint via WMI, leveraging PowerShell Script Block Logging (EventCode=4104). This method identifies specific script block text patterns associated with remote process instantiation. This activity is significant as it may indicate lateral movement or remote code execution attempts by adversaries. If confirmed malicious, this could allow attackers to execute arbitrary code on remote systems, potentially leading to further compromise and persistence within the network.

## MITRE ATT&CK

- T1047

## Analytic Stories

- Active Directory Lateral Movement

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1047/lateral_movement/wmi_remote_process_powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/remote_process_instantiation_via_wmi_and_powershell_script_block.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
