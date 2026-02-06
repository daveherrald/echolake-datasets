# Remote Process Instantiation via WMI and PowerShell

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of `powershell.exe` using the `Invoke-WmiMethod` cmdlet to start a process on a remote endpoint via WMI. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions and process telemetry. This activity is significant as it indicates potential lateral movement or remote code execution attempts by adversaries. If confirmed malicious, this could allow attackers to execute arbitrary code on remote systems, leading to further compromise and persistence within the network.

## MITRE ATT&CK

- T1047

## Analytic Stories

- Active Directory Lateral Movement
- Compromised Windows Host

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1047/lateral_movement/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/remote_process_instantiation_via_wmi_and_powershell.yml)*
