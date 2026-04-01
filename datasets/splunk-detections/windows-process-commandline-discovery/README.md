# Windows Process Commandline Discovery

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the use of Windows Management Instrumentation Command-line (WMIC) to retrieve information about running processes, specifically targeting the command lines used to launch those processes. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on logs containing process details and command-line executions. This activity is significant as it may indicate suspicious behavior, such as a user or process gathering detailed process information, which is uncommon for non-technical users. If confirmed malicious, this could allow an attacker to gain insights into running processes, aiding in further exploitation or lateral movement.

## MITRE ATT&CK

- T1057

## Analytic Stories

- CISA AA23-347A

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1057/process_commandline_discovery/wmic-cmdline-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_process_commandline_discovery.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
