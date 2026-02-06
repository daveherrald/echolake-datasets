# Process Kill Base On File Path

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the use of `wmic.exe` with the `delete` command to remove an executable path. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names, parent processes, and command-line executions. This activity is significant because it often indicates the initial stages of an adversary setting up malicious activities, such as cryptocurrency mining, on an endpoint. If confirmed malicious, this behavior could allow an attacker to disable security tools or other critical processes, facilitating further compromise and persistence within the environment.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- XMRig

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/process_kill_base_on_file_path.yml)*
