# Windows MSIExec Spawn WinDBG

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying the unusual behavior of MSIExec spawning WinDBG. It detects this activity by analyzing endpoint telemetry data, specifically looking for instances where 'msiexec.exe' is the parent process of 'windbg.exe'. This behavior is significant as it may indicate an attempt to debug or tamper with system processes, which is uncommon in typical user activity and could signify malicious intent. If confirmed malicious, this activity could allow an attacker to manipulate or inspect running processes, potentially leading to privilege escalation or persistence within the environment.

## MITRE ATT&CK

- T1218.007

## Analytic Stories

- Compromised Windows Host
- DarkGate Malware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.007/atomic_red_team/windbg_msiexec.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_msiexec_spawn_windbg.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
