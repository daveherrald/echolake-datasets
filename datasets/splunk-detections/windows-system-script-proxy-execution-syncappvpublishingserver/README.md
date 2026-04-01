# Windows System Script Proxy Execution Syncappvpublishingserver

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of Syncappvpublishingserver.vbs via wscript.exe or cscript.exe, which may indicate an attempt to download remote files or perform privilege escalation. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. Monitoring this activity is crucial as it can signify malicious use of a native Windows script for unauthorized actions. If confirmed malicious, this behavior could lead to unauthorized file downloads or elevated privileges, posing a significant security risk.

## MITRE ATT&CK

- T1216
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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1216/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_system_script_proxy_execution_syncappvpublishingserver.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
