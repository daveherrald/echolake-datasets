# Windows MSIExec Spawn Discovery Command

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting MSIExec spawning multiple discovery commands, such as Cmd.exe or PowerShell.exe. This behavior is identified using data from Endpoint Detection and Response (EDR) agents, focusing on process creation events where MSIExec is the parent process. This activity is significant because MSIExec typically does not spawn child processes other than itself, making this behavior highly suspicious. If confirmed malicious, an attacker could use these discovery commands to gather system information, potentially leading to further exploitation or lateral movement within the network.

## MITRE ATT&CK

- T1218.007

## Analytic Stories

- Windows System Binary Proxy Execution MSIExec
- Medusa Ransomware
- Water Gamayun
- StealC Stealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.007/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_msiexec_spawn_discovery_command.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
