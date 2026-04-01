# Windows WinDBG Spawning AutoIt3

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying instances of the WinDBG process spawning AutoIt3. This behavior is detected by monitoring endpoint telemetry for processes where 'windbg.exe' is the parent process and 'autoit3.exe' or similar is the child process. This activity is significant because AutoIt3 is frequently used by threat actors for scripting malicious automation, potentially indicating an ongoing attack. If confirmed malicious, this could allow attackers to automate tasks, execute arbitrary code, and further compromise the system, leading to data exfiltration or additional malware deployment.

## MITRE ATT&CK

- T1059

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/autoit/windbg_autoit.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_windbg_spawning_autoit3.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
