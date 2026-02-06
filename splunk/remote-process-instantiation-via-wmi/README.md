# Remote Process Instantiation via WMI

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of wmic.exe with parameters to spawn a process on a remote system. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions and process telemetry mapped to the `Processes` node of the `Endpoint` data model. This activity is significant as WMI can be abused for lateral movement and remote code execution, often used by adversaries and Red Teams. If confirmed malicious, this could allow attackers to execute arbitrary code on remote systems, facilitating further compromise and lateral spread within the network.

## MITRE ATT&CK

- T1047

## Analytic Stories

- CISA AA23-347A
- China-Nexus Threat Activity
- Ransomware
- Suspicious WMI Use
- Salt Typhoon
- Active Directory Lateral Movement

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1047/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/remote_process_instantiation_via_wmi.yml)*
