# Impacket Lateral Movement WMIExec Commandline Parameters

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the use of Impacket's `wmiexec.py` tool for lateral movement by identifying specific command-line parameters. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on processes spawned by `wmiprvse.exe` with command-line patterns indicative of Impacket usage. This activity is significant as Impacket tools are commonly used by adversaries for remote code execution and lateral movement within a network. If confirmed malicious, this could allow attackers to execute arbitrary commands on remote systems, potentially leading to further compromise and data exfiltration.

## MITRE ATT&CK

- T1021.002
- T1021.003
- T1047
- T1543.003

## Analytic Stories

- WhisperGate
- Gozi Malware
- Active Directory Lateral Movement
- Volt Typhoon
- Prestige Ransomware
- Industroyer2
- Data Destruction
- Graceful Wipe Out Attack
- Compromised Windows Host
- CISA AA22-277A
- Storm-0501 Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.002/atomic_red_team/wmiexec_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/impacket_lateral_movement_wmiexec_commandline_parameters.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
