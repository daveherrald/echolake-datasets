# Windows DLL Module Loaded in Temp Dir

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting instances where a Dynamic Link Library (DLL) is loaded from a temporary directory on a Windows system. Loading DLLs from non-standard paths such as %TEMP% is uncommon for legitimate applications and is often associated with adversary tradecraft, including DLL search order hijacking, side-loading, or execution of malicious payloads staged in temporary folders. Adversaries frequently leverage these directories because they are writable by standard users and often overlooked by security controls, making them convenient locations to drop and execute malicious files. This behavior may indicate attempts to evade detection, execute unauthorized code, or maintain persistence through hijacked execution flows. Detection of DLL loads from %TEMP% can help surface early signs of compromise and should be investigated in the context of the originating process, user account, and potential file creation or modification activity within the same directory.

## MITRE ATT&CK

- T1105

## Analytic Stories

- Interlock Rat
- Lokibot

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/dll_loaded_in_temp/module_loaded_in_temp.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_dll_module_loaded_in_temp_dir.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
