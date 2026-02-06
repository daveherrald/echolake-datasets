# Windows Service Initiation on Remote Endpoint

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of `sc.exe` with command-line arguments used to start a Windows Service on a remote endpoint. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant because adversaries may exploit the Service Control Manager for lateral movement and remote code execution. If confirmed malicious, this could allow attackers to execute arbitrary code on remote systems, potentially leading to further compromise and persistence within the network.

## MITRE ATT&CK

- T1543.003

## Analytic Stories

- Active Directory Lateral Movement
- CISA AA23-347A

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1543.003/lateral_movement/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_service_initiation_on_remote_endpoint.yml)*
