# Windows InstallUtil URL in Command Line

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the use of Windows InstallUtil.exe with an HTTP or HTTPS URL in the command line. This is identified through Endpoint Detection and Response (EDR) telemetry, focusing on command-line executions containing URLs. This activity is significant as it may indicate an attempt to download and execute malicious code, potentially bypassing application control mechanisms. If confirmed malicious, this could lead to unauthorized code execution, privilege escalation, or persistent access within the environment. Analysts should review the parent process, network connections, file modifications, and related processes for further investigation.

## MITRE ATT&CK

- T1218.004

## Analytic Stories

- Living Off The Land
- Compromised Windows Host
- Signed Binary Proxy Execution InstallUtil
- Cisco Network Visibility Module Analytics

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2
- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.004/atomic_red_team/windows-sysmon.log

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_installutil_url_in_command_line.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
