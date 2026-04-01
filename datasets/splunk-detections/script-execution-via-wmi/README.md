# Script Execution via WMI

**Type:** TTP

**Author:** Rico Valdez, Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of scripts via Windows Management Instrumentation (WMI) by monitoring the process 'scrcons.exe'. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events. WMI-based script execution is significant because adversaries often use it to perform malicious activities stealthily, such as system compromise, data exfiltration, or establishing persistence. If confirmed malicious, this activity could allow attackers to execute arbitrary code, escalate privileges, or maintain long-term access to the environment. Analysts should differentiate between legitimate administrative use and potential threats.

## MITRE ATT&CK

- T1047

## Analytic Stories

- Suspicious WMI Use
- Scattered Spider

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1047/execution_scrcons/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/script_execution_via_wmi.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
