# Windows Hijack Execution Flow Version Dll Side Load

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a process loading a version.dll file from a directory other than %windir%\system32 or %windir%\syswow64. This detection leverages Sysmon EventCode 7 to identify instances where an unsigned or improperly located version.dll is loaded. This activity is significant as it is a common technique used in ransomware and APT malware campaigns, including Brute Ratel C4, to execute malicious code via DLL side loading. If confirmed malicious, this could allow attackers to execute arbitrary code, maintain persistence, and potentially compromise the target host.

## MITRE ATT&CK

- T1574.001

## Analytic Stories

- Brute Ratel C4
- XWorm
- Malicious Inno Setup Loader

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/brute_ratel/iso_version_dll_campaign/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_hijack_execution_flow_version_dll_side_load.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
