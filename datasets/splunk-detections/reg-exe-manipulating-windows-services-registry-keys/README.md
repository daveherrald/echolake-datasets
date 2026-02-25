# Reg exe Manipulating Windows Services Registry Keys

**Type:** TTP

**Author:** Rico Valdez, Splunk

## Description

This dataset contains sample data for detecting the use of reg.exe to modify registry keys associated with Windows services and their configurations. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names, parent processes, and command-line executions. This activity is significant because unauthorized changes to service registry keys can indicate an attempt to establish persistence or escalate privileges. If confirmed malicious, this could allow an attacker to control service behavior, potentially leading to unauthorized code execution or system compromise.

## MITRE ATT&CK

- T1574.011

## Analytic Stories

- Windows Service Abuse
- Windows Persistence Techniques
- Living Off The Land

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1574.011/change_registry_path_service/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/reg_exe_manipulating_windows_services_registry_keys.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
