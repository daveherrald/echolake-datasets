# Ryuk Wake on LAN Command

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the use of Wake-on-LAN commands associated with Ryuk ransomware. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on specific process and command-line activities. This behavior is significant as Ryuk ransomware uses Wake-on-LAN to power on devices in a compromised network, increasing its encryption success rate. If confirmed malicious, this activity could lead to widespread ransomware encryption across multiple endpoints, causing significant operational disruption and data loss. Immediate isolation and thorough investigation of the affected endpoints are crucial to mitigate the impact.

## MITRE ATT&CK

- T1059.003

## Analytic Stories

- Compromised Windows Host
- Ryuk Ransomware
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.003/ryuk/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/ryuk_wake_on_lan_command.yml)*
