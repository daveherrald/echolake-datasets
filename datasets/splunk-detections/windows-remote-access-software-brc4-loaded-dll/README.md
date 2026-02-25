# Windows Remote Access Software BRC4 Loaded Dll

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying the loading of four specific Windows DLLs (credui.dll, dbghelp.dll, samcli.dll, winhttp.dll) by a non-standard process. This detection leverages Sysmon EventCode 7 to monitor DLL load events and flags when all four DLLs are loaded within a short time frame. This activity is significant as it may indicate the presence of Brute Ratel C4, a sophisticated remote access tool used for credential dumping and other malicious activities. If confirmed malicious, this behavior could lead to unauthorized access, credential theft, and further compromise of the affected system.

## MITRE ATT&CK

- T1219
- T1003

## Analytic Stories

- Brute Ratel C4

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/brute_ratel/iso_version_dll_campaign/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_remote_access_software_brc4_loaded_dll.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
