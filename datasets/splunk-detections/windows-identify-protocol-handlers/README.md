# Windows Identify Protocol Handlers

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying the use of protocol handlers executed via the command line. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and command-line telemetry. This activity is significant because protocol handlers can be exploited to execute arbitrary commands or launch applications, potentially leading to unauthorized actions. If confirmed malicious, an attacker could use this technique to gain code execution, escalate privileges, or maintain persistence within the environment, posing a significant security risk.

## MITRE ATT&CK

- T1059

## Analytic Stories

- Living Off The Land

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/protocol_handlers/protocolhandlers.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_identify_protocol_handlers.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
