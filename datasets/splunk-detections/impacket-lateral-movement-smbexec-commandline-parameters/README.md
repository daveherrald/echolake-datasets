# Impacket Lateral Movement smbexec CommandLine Parameters

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying suspicious command-line parameters associated with the use of Impacket's smbexec.py for lateral movement. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on specific command-line patterns indicative of Impacket tool usage. This activity is significant as both Red Teams and adversaries use Impacket for remote code execution and lateral movement. If confirmed malicious, this activity could allow attackers to execute commands on remote endpoints, potentially leading to unauthorized access, data exfiltration, or further compromise of the network.

## MITRE ATT&CK

- T1021.002
- T1021.003
- T1047
- T1543.003

## Analytic Stories

- WhisperGate
- Active Directory Lateral Movement
- Volt Typhoon
- Prestige Ransomware
- Industroyer2
- Data Destruction
- Graceful Wipe Out Attack
- Compromised Windows Host
- CISA AA22-277A

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.002/atomic_red_team/smbexec_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/impacket_lateral_movement_smbexec_commandline_parameters.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
