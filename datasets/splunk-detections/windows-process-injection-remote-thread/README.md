# Windows Process Injection Remote Thread

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious remote thread execution in processes such as Taskmgr.exe, calc.exe, and notepad.exe, which may indicate process injection by malware like Qakbot. This detection leverages Sysmon EventCode 8 to identify remote thread creation in specific target processes. This activity is significant as it often signifies an attempt by malware to inject malicious code into legitimate processes, potentially leading to unauthorized code execution. If confirmed malicious, this could allow attackers to execute arbitrary code, escalate privileges, or maintain persistence on the compromised host.

## MITRE ATT&CK

- T1055.002

## Analytic Stories

- Qakbot
- Graceful Wipe Out Attack
- Warzone RAT
- Earth Alux
- Water Gamayun

## Data Sources

- Sysmon EventID 8

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/qakbot/qbot_wermgr2/sysmon_wermgr2.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_process_injection_remote_thread.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
