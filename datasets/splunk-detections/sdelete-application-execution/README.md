# Sdelete Application Execution

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of the sdelete.exe application, a Sysinternals tool often used by adversaries to securely delete files and remove forensic evidence from a targeted host. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs. Monitoring this activity is crucial as sdelete.exe is not commonly used in regular operations and its presence may indicate an attempt to cover malicious activities. If confirmed malicious, this could lead to the loss of critical forensic data, hindering incident response and investigation efforts.

## MITRE ATT&CK

- T1070.004
- T1485

## Analytic Stories

- Masquerading - Rename System Utilities
- Scattered Spider

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/sdelete/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/sdelete_application_execution.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
