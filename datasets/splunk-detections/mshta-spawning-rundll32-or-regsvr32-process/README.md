# Mshta spawning Rundll32 OR Regsvr32 Process

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a suspicious mshta.exe process spawning rundll32 or regsvr32 child processes. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process GUID, process name, and parent process fields. This activity is significant as it is a known technique used by malware like Trickbot to load malicious DLLs and execute payloads. If confirmed malicious, this behavior could allow attackers to execute arbitrary code, escalate privileges, or download additional malware, posing a severe threat to the environment.

## MITRE ATT&CK

- T1218.005

## Analytic Stories

- Trickbot
- IcedID
- Living Off The Land
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/spear_phish/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/mshta_spawning_rundll32_or_regsvr32_process.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
