# Windows Chromium Process Loaded Extension via Command-Line

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting instances where Google Chrome is started with the --load-extension command-line flag, which allows loading unpacked or non-standard extensions. This behavior can indicate attempts to bypass enterprise extension policies, install malicious extensions, or load potentially harmful browser components. Monitoring such activity helps identify unauthorized extension usage, potential malware persistence mechanisms, or policy violations that could compromise browser security.


## MITRE ATT&CK

- T1185

## Analytic Stories

- Browser Hijacking

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1185/chrome_load_extensions/chrome_load_extension.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_chromium_process_loaded_extension_via_command_line.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
