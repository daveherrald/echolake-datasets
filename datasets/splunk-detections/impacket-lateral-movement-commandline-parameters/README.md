# Impacket Lateral Movement Commandline Parameters

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying the use of suspicious command-line parameters associated with Impacket tools, such as `wmiexec.py`, `smbexec.py`, `dcomexec.py`, and `atexec.py`, which are used for lateral movement and remote code execution. It detects these activities by analyzing process execution logs from Endpoint Detection and Response (EDR) agents, focusing on specific command-line patterns. This activity is significant because Impacket tools are commonly used by adversaries and Red Teams to move laterally within a network. If confirmed malicious, this could allow attackers to execute commands remotely, potentially leading to further compromise and data exfiltration.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.003/impacket/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/impacket_lateral_movement_commandline_parameters.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
