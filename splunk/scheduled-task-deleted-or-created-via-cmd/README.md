# Scheduled Task Deleted Or Created via CMD

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

The following analytic identifies the creation or deletion of scheduled tasks using the schtasks.exe utility with the -create or -delete flags. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as it can indicate unauthorized system manipulation or malicious intent, often associated with threat actors like Dragonfly and incidents such as the SUNBURST attack. If confirmed malicious, this activity could allow attackers to execute code, escalate privileges, or persist within the environment, posing a significant security risk.

## MITRE ATT&CK

- T1053.005

## Analytic Stories

- ShrinkLocker
- AgentTesla
- CISA AA24-241A
- Winter Vivern
- Quasar RAT
- Rhysida Ransomware
- Sandworm Tools
- DarkCrystal RAT
- Qakbot
- China-Nexus Threat Activity
- XWorm
- CISA AA23-347A
- Azorult
- Living Off The Land
- Salt Typhoon
- Trickbot
- NOBELIUM Group
- CISA AA22-257A
- Medusa Ransomware
- Phemedrone Stealer
- NjRAT
- DHS Report TA18-074A
- Scheduled Tasks
- Prestige Ransomware
- Amadey
- AsyncRAT
- RedLine Stealer
- Windows Persistence Techniques
- MoonPeak
- Scattered Spider
- 0bj3ctivity Stealer
- APT37 Rustonotto and FadeStealer
- Lokibot
- NetSupport RMM Tool Abuse
- ValleyRAT
- PlugX
- Remcos

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/scheduled_task_deleted_or_created_via_cmd.yml)*
