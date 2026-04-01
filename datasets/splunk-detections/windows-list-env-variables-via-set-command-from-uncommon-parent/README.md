# Windows List ENV Variables Via SET Command From Uncommon Parent

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying a suspicious process command line fetching environment variables using the cmd.exe "set" command, with a non-shell parent process. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions and parent process names. This activity could be significant as it is commonly associated with malware like Qakbot, which uses this technique to gather system information. If confirmed malicious, this behavior could indicate that the parent process has been compromised, potentially allowing attackers to execute arbitrary commands, escalate privileges, or persist within the environment.

## MITRE ATT&CK

- T1055

## Analytic Stories

- Qakbot

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/qakbot/qbot_wermgr/sysmon_wermgr.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_list_env_variables_via_set_command_from_uncommon_parent.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
