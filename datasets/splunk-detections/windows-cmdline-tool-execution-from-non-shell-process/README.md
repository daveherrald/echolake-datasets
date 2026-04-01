# Windows Cmdline Tool Execution From Non-Shell Process

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying instances where `ipconfig.exe`, `systeminfo.exe`, or similar tools are executed by a non-standard shell parent process, excluding CMD, PowerShell, or Explorer. This detection leverages Endpoint Detection and Response (EDR) telemetry to monitor process creation events. Such behavior is significant as it may indicate adversaries using injected processes to perform system discovery, a tactic observed in FIN7's JSSLoader. If confirmed malicious, this activity could allow attackers to gather critical host information, aiding in further exploitation or lateral movement within the network.

## MITRE ATT&CK

- T1059.007

## Analytic Stories

- CISA AA22-277A
- Gozi Malware
- CISA AA23-347A
- Qakbot
- Medusa Ransomware
- DarkGate Malware
- Rhysida Ransomware
- Volt Typhoon
- FIN7
- Water Gamayun
- Tuoni

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/fin7/jssloader/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_cmdline_tool_execution_from_non_shell_process.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
