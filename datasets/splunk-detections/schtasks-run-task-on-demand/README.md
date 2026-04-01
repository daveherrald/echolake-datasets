# Schtasks Run Task On Demand

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of a Windows Scheduled Task on demand via the shell or command line. It leverages process-related data, including process name, parent process, and command-line executions, sourced from endpoint logs. The detection focuses on 'schtasks.exe' with an associated 'run' command. This activity is significant as adversaries often use it to force the execution of their created Scheduled Tasks for persistent access or lateral movement within a compromised machine. If confirmed malicious, this could allow attackers to maintain persistence or move laterally within the network, potentially leading to further compromise.

## MITRE ATT&CK

- T1053

## Analytic Stories

- Industroyer2
- CISA AA22-257A
- Data Destruction
- Qakbot
- XMRig
- Medusa Ransomware
- Scheduled Tasks

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/schtasks_run_task_on_demand.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
