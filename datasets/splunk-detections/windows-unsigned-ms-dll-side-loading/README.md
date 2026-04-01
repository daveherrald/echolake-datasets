# Windows Unsigned MS DLL Side-Loading

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying potential DLL side-loading instances involving unsigned DLLs mimicking Microsoft signatures. It detects this activity by analyzing Sysmon logs for Event Code 7, where both the `Image` and `ImageLoaded` paths do not match system directories like `system32`, `syswow64`, and `programfiles`. This behavior is significant as adversaries often exploit DLL side-loading to execute malicious code via legitimate processes. If confirmed malicious, this activity could allow attackers to execute arbitrary code, potentially leading to privilege escalation, persistence, and unauthorized access to sensitive information.

## MITRE ATT&CK

- T1574.001
- T1547

## Analytic Stories

- China-Nexus Threat Activity
- Derusbi
- APT29 Diplomatic Deceptions with WINELOADER
- Salt Typhoon
- Earth Alux
- XWorm

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1574.002/unsigned_dll_load//wineloader_dll_sideload.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_unsigned_ms_dll_side_loading.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
