# Windows MSIExec DLLRegisterServer

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of msiexec.exe with the /y switch parameter, which enables the loading of DLLRegisterServer. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process command-line arguments and parent-child process relationships. This activity is significant because it can indicate an attempt to register malicious DLLs, potentially leading to code execution or persistence on the system. If confirmed malicious, this could allow an attacker to execute arbitrary code, escalate privileges, or maintain persistence within the environment.

## MITRE ATT&CK

- T1218.007

## Analytic Stories

- Windows System Binary Proxy Execution MSIExec
- Water Gamayun

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.007/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_msiexec_dllregisterserver.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
