# Process Execution via WMI

**Type:** TTP

**Author:** Rico Valdez, Michael Haag, Splunk

## Description

The following analytic detects the execution of a process by `WmiPrvSE.exe`, indicating potential use of WMI (Windows Management Instrumentation) for process creation. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and parent process relationships. This activity is significant as WMI can be used for lateral movement, remote code execution, or persistence by attackers. If confirmed malicious, this could allow an attacker to execute arbitrary commands or scripts, potentially leading to further compromise of the affected system or network.

## MITRE ATT&CK

- T1047

## Analytic Stories

- Suspicious WMI Use

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1047/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/process_execution_via_wmi.yml)*
