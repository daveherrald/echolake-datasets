# Windows Svchost.exe Parent Process Anomaly

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting an anomaly where an svchost.exe process is spawned by a parent process other than the standard services.exe. In a typical Windows environment, svchost.exe is a system process that hosts Windows service DLLs, and is expected to be a child of services.exe. A process deviation from this hierarchy may indicate suspicious behavior, such as malicious code attempting to masquerade as a legitimate system process or evade detection. It is essential to investigate the parent process and associated behavior for further signs of compromise or unauthorized activity.

## MITRE ATT&CK

- T1036.009

## Analytic Stories

- SnappyBee
- China-Nexus Threat Activity

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1035.009/suspicious_spawn_svchost/susp_svchost_proc.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_svchost_exe_parent_process_anomaly.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
