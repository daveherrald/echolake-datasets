# Remote Process Instantiation via DCOM and PowerShell

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of `powershell.exe` with arguments used to start a process on a remote endpoint by abusing the DCOM protocol, specifically targeting ShellExecute and ExecuteShellCommand. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names, parent processes, and command-line executions. This activity is significant as it indicates potential lateral movement and remote code execution attempts by adversaries. If confirmed malicious, this could allow attackers to execute arbitrary code remotely, escalate privileges, and move laterally within the network, posing a severe security risk.

## MITRE ATT&CK

- T1021.003

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.003/lateral_movement/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/remote_process_instantiation_via_dcom_and_powershell.yml)*
