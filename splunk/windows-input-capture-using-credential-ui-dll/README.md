# Windows Input Capture Using Credential UI Dll

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects a process loading the credui.dll or wincredui.dll module. This detection leverages Sysmon EventCode 7 to identify instances where these DLLs are loaded by processes outside typical system directories. This activity is significant because adversaries often abuse these modules to create fake credential prompts or dump credentials, posing a risk of credential theft. If confirmed malicious, this activity could allow attackers to harvest user credentials, leading to unauthorized access and potential lateral movement within the network.

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
