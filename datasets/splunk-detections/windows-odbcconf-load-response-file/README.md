# Windows Odbcconf Load Response File

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of odbcconf.exe with a response file, which may contain commands to load a DLL (REGSVR) or other instructions. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. This activity is significant as it may indicate an attempt to execute arbitrary code or load malicious DLLs, potentially leading to unauthorized actions. If confirmed malicious, this could allow an attacker to gain code execution, escalate privileges, or establish persistence within the environment.

## MITRE ATT&CK

- T1218.008

## Analytic Stories

- Living Off The Land

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.008/atomic_red_team/windows-sysmon-odbc-rsp.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_odbcconf_load_response_file.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
