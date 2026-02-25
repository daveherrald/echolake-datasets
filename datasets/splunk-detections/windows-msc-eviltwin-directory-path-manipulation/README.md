# Windows MSC EvilTwin Directory Path Manipulation

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting potential MSC EvilTwin loader exploitation, which manipulates directory paths with spaces to bypass security controls. The technique, described as CVE-2025-26633, involves crafting malicious MSC files that leverage MUIPath parameter manipulation. This detection focuses on suspicious MSC file execution patterns with unconventional command-line parameters, particularly those containing unusual spaces in Windows System32 paths or suspicious additional parameters after the MSC file. If confirmed malicious, this behavior could allow an attacker to execute arbitrary code with elevated privileges through DLL side-loading or path traversal techniques.

## MITRE ATT&CK

- T1218
- T1036.005
- T1203

## Analytic Stories

- Water Gamayun
- Windows Defense Evasion Tactics
- Living Off The Land

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218/eviltwin/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_msc_eviltwin_directory_path_manipulation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
