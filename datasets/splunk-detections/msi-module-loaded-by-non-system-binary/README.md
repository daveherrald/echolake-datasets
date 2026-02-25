# MSI Module Loaded by Non-System Binary

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the loading of `msi.dll` by a binary not located in `system32`, `syswow64`, `winsxs`, or `windows` directories. This is identified using Sysmon EventCode 7, which logs DLL loads, and filters out legitimate system paths. This activity is significant as it may indicate exploitation of CVE-2021-41379 or DLL side-loading attacks, both of which can lead to unauthorized system modifications. If confirmed malicious, this could allow an attacker to execute arbitrary code, escalate privileges, or persist within the environment.

## MITRE ATT&CK

- T1574.001

## Analytic Stories

- Data Destruction
- Hermetic Wiper
- Windows Privilege Escalation

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1574.002/msi_module_load/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/msi_module_loaded_by_non_system_binary.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
