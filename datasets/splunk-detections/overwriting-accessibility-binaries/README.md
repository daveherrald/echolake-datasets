# Overwriting Accessibility Binaries

**Type:** TTP

**Author:** David Dorsey, Splunk

## Description

This dataset contains sample data for detecting modifications to Windows accessibility binaries such as sethc.exe, utilman.exe, osk.exe, Magnify.exe, Narrator.exe, DisplaySwitch.exe, and AtBroker.exe. It leverages filesystem activity data from the Endpoint.Filesystem data model to identify changes to these specific files. This activity is significant because adversaries can exploit these binaries to gain unauthorized access or execute commands without logging in. If confirmed malicious, this could allow attackers to bypass authentication mechanisms, potentially leading to unauthorized system access and further compromise of the environment.

## MITRE ATT&CK

- T1546.008

## Analytic Stories

- Data Destruction
- Hermetic Wiper
- Windows Privilege Escalation
- Flax Typhoon

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.008/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/overwriting_accessibility_binaries.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
