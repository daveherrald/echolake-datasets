# Windows Indirect Command Execution Via forfiles

**Type:** TTP

**Author:** Eric McGinnis, Splunk

## Description

This dataset contains sample data for detecting the execution of programs initiated by forfiles.exe. This command is typically used to run commands on multiple files, often within batch scripts. The detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events where forfiles.exe is the parent process. This activity is significant because forfiles.exe can be exploited to bypass command line execution protections, making it a potential vector for malicious activity. If confirmed malicious, this could allow attackers to execute arbitrary commands, potentially leading to unauthorized access or further system compromise.

## MITRE ATT&CK

- T1202

## Analytic Stories

- Living Off The Land
- Windows Post-Exploitation

## Data Sources

- Sysmon EventID 1
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1202/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_indirect_command_execution_via_forfiles.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
