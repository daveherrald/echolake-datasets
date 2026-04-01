# Windows Driver Load Non-Standard Path

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the loading of new Kernel Mode Drivers from non-standard paths using Windows EventCode 7045. It identifies drivers not located in typical directories like Windows, Program Files, or SystemRoot. This activity is significant because adversaries may use these non-standard paths to load malicious or vulnerable drivers, potentially bypassing security controls. If confirmed malicious, this could allow attackers to execute code at the kernel level, escalate privileges, or maintain persistence within the environment, posing a severe threat to system integrity and security.

## MITRE ATT&CK

- T1014
- T1068

## Analytic Stories

- Windows Drivers
- CISA AA22-320A
- AgentTesla
- BlackByte Ransomware
- BlackSuit Ransomware

## Data Sources

- Windows Event Log System 7045

## Sample Data

- **Source:** XmlWinEventLog:System
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1068/drivers/xml7045_windows-system.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_driver_load_non_standard_path.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
