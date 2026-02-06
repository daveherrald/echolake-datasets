# Remote Process Instantiation via WinRM and PowerShell Script Block

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of PowerShell commands that use the `Invoke-Command` cmdlet to start a process on a remote endpoint via the WinRM protocol. It leverages PowerShell Script Block Logging (EventCode=4104) to identify such activities. This behavior is significant as it may indicate lateral movement or remote code execution attempts by adversaries. If confirmed malicious, this activity could allow attackers to execute arbitrary code on remote systems, potentially leading to further compromise and persistence within the network.

## MITRE ATT&CK

- T1021.006

## Analytic Stories

- Active Directory Lateral Movement

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.006/lateral_movement_psh/windows-powershell-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/remote_process_instantiation_via_winrm_and_powershell_script_block.yml)*
