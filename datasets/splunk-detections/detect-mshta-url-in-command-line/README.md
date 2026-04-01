# Detect MSHTA Url in Command Line

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the use of Microsoft HTML Application Host (mshta.exe) to make remote HTTP or HTTPS connections. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line arguments containing URLs. This activity is significant because adversaries often use mshta.exe to download and execute remote .hta files, bypassing security controls. If confirmed malicious, this behavior could allow attackers to execute arbitrary code, potentially leading to system compromise, data exfiltration, or further network infiltration.

## MITRE ATT&CK

- T1218.005

## Analytic Stories

- APT37 Rustonotto and FadeStealer
- Compromised Windows Host
- Lumma Stealer
- Living Off The Land
- Suspicious MSHTA Activity
- XWorm
- Cisco Network Visibility Module Analytics
- NetSupport RMM Tool Abuse

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2
- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.005/atomic_red_team/windows-sysmon.log

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_mshta_url_in_command_line.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
