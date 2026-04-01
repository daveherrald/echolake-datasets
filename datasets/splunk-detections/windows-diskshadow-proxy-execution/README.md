# Windows Diskshadow Proxy Execution

**Type:** TTP

**Author:** Lou Stella, Splunk

## Description

This dataset contains sample data for detecting the use of DiskShadow.exe in scripting mode, which can execute arbitrary unsigned code. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions with scripting mode flags. This activity is significant because DiskShadow.exe is typically used for legitimate backup operations, but its misuse can indicate an attempt to execute unauthorized code. If confirmed malicious, this could lead to unauthorized code execution, potentially compromising the system and allowing further malicious activities.

## MITRE ATT&CK

- T1218

## Analytic Stories

- Living Off The Land

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218/diskshadow/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_diskshadow_proxy_execution.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
