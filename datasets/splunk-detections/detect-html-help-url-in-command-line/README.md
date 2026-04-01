# Detect HTML Help URL in Command Line

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of hh.exe (HTML Help) loading a Compiled HTML Help (CHM) file from a remote URL. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions containing URLs. This activity is significant as it can indicate an attempt to execute malicious scripts via CHM files, potentially leading to unauthorized code execution. If confirmed malicious, this could allow an attacker to run scripts using engines like JScript or VBScript, leading to further system compromise or data exfiltration.

## MITRE ATT&CK

- T1218.001

## Analytic Stories

- APT37 Rustonotto and FadeStealer
- Suspicious Compiled HTML Activity
- Living Off The Land
- Compromised Windows Host
- Cisco Network Visibility Module Analytics

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2
- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.001/atomic_red_team/windows-sysmon.log

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_html_help_url_in_command_line.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
