# Windows Debugger Tool Execution

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

This analysis detects the use of debugger tools within a production environment. While these tools are legitimate for file analysis and debugging, they are abused by malware like PlugX and DarkGate for malicious DLL side-loading. The hunting query aids Security Operations Centers (SOCs) in identifying potentially suspicious tool executions, particularly for non-technical users in the production network.

## MITRE ATT&CK

- T1036

## Analytic Stories

- DarkGate Malware
- PlugX

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036/debugger_execution/debugger.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_debugger_tool_execution.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
