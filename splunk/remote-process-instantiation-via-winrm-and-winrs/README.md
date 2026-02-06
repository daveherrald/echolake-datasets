# Remote Process Instantiation via WinRM and Winrs

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of `winrs.exe` with command-line arguments used to start a process on a remote endpoint. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions mapped to the `Processes` node of the `Endpoint` data model. This activity is significant as it may indicate lateral movement or remote code execution attempts by adversaries. If confirmed malicious, this could allow attackers to execute arbitrary code on remote systems, potentially leading to further compromise and lateral spread within the network.

## MITRE ATT&CK

- T1021.006

## Analytic Stories

- Active Directory Lateral Movement

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.006/lateral_movement/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/remote_process_instantiation_via_winrm_and_winrs.yml)*
