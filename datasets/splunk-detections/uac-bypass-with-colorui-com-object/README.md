# UAC Bypass With Colorui COM Object

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a potential UAC bypass using the colorui.dll COM Object. It leverages Sysmon EventCode 7 to identify instances where colorui.dll is loaded by a process other than colorcpl.exe, excluding common system directories. This activity is significant because UAC bypass techniques are often used by malware, such as LockBit ransomware, to gain elevated privileges without user consent. If confirmed malicious, this could allow an attacker to execute code with higher privileges, leading to further system compromise and persistence within the environment.

## MITRE ATT&CK

- T1218.003

## Analytic Stories

- Ransomware
- LockBit Ransomware

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.015/uac_colorui/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/uac_bypass_with_colorui_com_object.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
