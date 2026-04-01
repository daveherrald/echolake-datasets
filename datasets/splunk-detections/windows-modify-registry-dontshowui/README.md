# Windows Modify Registry DontShowUI

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting modifications to the Windows Error Reporting registry key "DontShowUI" to suppress error reporting dialogs. It leverages data from the Endpoint datamodel's Registry node to identify changes where the registry value is set to 0x00000001. This activity is significant as it is commonly associated with DarkGate malware, which uses this modification to avoid detection during its installation. If confirmed malicious, this behavior could allow attackers to maintain a low profile, avoiding user alerts and potentially enabling further malicious activities without user intervention.

## MITRE ATT&CK

- T1112

## Analytic Stories

- DarkGate Malware

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/wer_dontshowui/dontshowui_sys.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_dontshowui.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
