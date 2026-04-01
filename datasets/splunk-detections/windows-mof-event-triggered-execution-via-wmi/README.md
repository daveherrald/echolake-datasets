# Windows MOF Event Triggered Execution via WMI

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of MOFComp.exe loading a MOF file, often triggered by cmd.exe or powershell.exe, or from unusual paths like User Profile directories. It leverages Endpoint Detection and Response (EDR) data, focusing on process names, parent processes, and command-line executions. This activity is significant as it may indicate an attacker using WMI for persistence or lateral movement. If confirmed malicious, it could allow the attacker to execute arbitrary code, maintain persistence, or escalate privileges within the environment.

## MITRE ATT&CK

- T1546.003

## Analytic Stories

- Living Off The Land
- Compromised Windows Host

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.003/atomic_red_team/mofcomp.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_mof_event_triggered_execution_via_wmi.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
