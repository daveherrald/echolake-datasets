# Msmpeng Application DLL Side Loading

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Sanjay Govind

## Description

This dataset contains sample data for detecting the suspicious creation of msmpeng.exe or mpsvc.dll in non-default Windows Defender folders. It leverages the Endpoint.Filesystem datamodel to identify instances where these files are created outside their expected directories. This activity is significant because it is associated with the REvil ransomware, which uses DLL side-loading to execute malicious payloads. If confirmed malicious, this could lead to ransomware deployment, resulting in data encryption, system compromise, and potential data loss or extortion.

## MITRE ATT&CK

- T1574.001

## Analytic Stories

- Ransomware
- Revil Ransomware

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets//malware/revil/msmpeng_side/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/msmpeng_application_dll_side_loading.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
