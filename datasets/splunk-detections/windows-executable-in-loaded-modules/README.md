# Windows Executable in Loaded Modules

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying instances where executable files (.exe) are loaded as modules, detected through 'ImageLoaded' events in Sysmon logs. This method leverages Sysmon EventCode 7 to track unusual module loading behavior, which is significant as it deviates from the norm of loading .dll files. This activity is crucial for SOC monitoring because it can indicate the presence of malware like NjRAT, which uses this technique to load malicious modules. If confirmed malicious, this behavior could allow attackers to execute arbitrary code, maintain persistence, and further compromise the host system.

## MITRE ATT&CK

- T1129

## Analytic Stories

- NjRAT
- Lokibot

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1129/executable_shared_modules/image_loaded_exe.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_executable_in_loaded_modules.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
