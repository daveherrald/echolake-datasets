# Suspicious mshta spawn

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the spawning of mshta.exe by wmiprvse.exe or svchost.exe. This behavior is identified using Endpoint Detection and Response (EDR) data, focusing on process creation events where the parent process is either wmiprvse.exe or svchost.exe. This activity is significant as it may indicate the use of a DCOM object to execute malicious scripts via mshta.exe, a common tactic in sophisticated attacks. If confirmed malicious, this could allow an attacker to execute arbitrary code, potentially leading to system compromise and further malicious activities.

## MITRE ATT&CK

- T1218.005

## Analytic Stories

- Suspicious MSHTA Activity
- Living Off The Land
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.005/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_mshta_spawn.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
