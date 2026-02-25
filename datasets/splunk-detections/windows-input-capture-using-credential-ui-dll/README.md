# Windows Input Capture Using Credential UI Dll

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a process loading the credui.dll or wincredui.dll module. This detection leverages Sysmon EventCode 7 to identify instances where these DLLs are loaded by processes outside typical system directories. This activity is significant because adversaries often abuse these modules to create fake credential prompts or dump credentials, posing a risk of credential theft. If confirmed malicious, this activity could allow attackers to harvest user credentials, leading to unauthorized access and potential lateral movement within the network.

## MITRE ATT&CK

- T1056.002

## Analytic Stories

- Brute Ratel C4
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/brute_ratel/iso_version_dll_campaign/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_input_capture_using_credential_ui_dll.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
