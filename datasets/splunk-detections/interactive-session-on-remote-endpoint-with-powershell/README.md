# Interactive Session on Remote Endpoint with PowerShell

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the use of the `Enter-PSSession` cmdlet to establish an interactive session on a remote endpoint via the WinRM protocol. It leverages PowerShell Script Block Logging (EventCode=4104) to identify this activity by searching for specific script block text patterns. This behavior is significant as it may indicate lateral movement or remote code execution attempts by adversaries. If confirmed malicious, this activity could allow attackers to execute commands remotely, potentially leading to further compromise of the network and unauthorized access to sensitive information.

## MITRE ATT&CK

- T1021.006

## Analytic Stories

- Active Directory Lateral Movement

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.006/lateral_movement_pssession/windows-powershell-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/interactive_session_on_remote_endpoint_with_powershell.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
