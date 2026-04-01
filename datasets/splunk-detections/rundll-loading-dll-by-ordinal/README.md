# RunDLL Loading DLL By Ordinal

**Type:** TTP

**Author:** Michael Haag, David Dorsey, Splunk

## Description

This dataset contains sample data for detecting rundll32.exe loading a DLL export function by ordinal value. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process command-line executions. This behavior is significant because adversaries may use rundll32.exe to execute malicious code while evading security tools that do not monitor this process. If confirmed malicious, this activity could allow attackers to execute arbitrary code, potentially leading to system compromise, privilege escalation, or persistent access within the environment.

## MITRE ATT&CK

- T1218.011

## Analytic Stories

- Unusual Processes
- Suspicious Rundll32 Activity
- Living Off The Land
- IcedID

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.011/atomic_red_team/ordinal_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/rundll_loading_dll_by_ordinal.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
