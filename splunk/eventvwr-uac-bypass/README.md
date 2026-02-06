# Eventvwr UAC Bypass

**Type:** TTP

**Author:** Steven Dick, Michael Haag, Splunk

## Description

The following analytic detects an Eventvwr UAC bypass by identifying suspicious registry modifications in the path that Eventvwr.msc references upon execution. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on registry changes and process execution details. This activity is significant because it indicates a potential privilege escalation attempt, allowing an attacker to execute arbitrary commands with elevated privileges. If confirmed malicious, this could lead to unauthorized code execution, persistence, and further compromise of the affected system.

## MITRE ATT&CK

- T1548.002

## Analytic Stories

- Windows Defense Evasion Tactics
- IcedID
- Living Off The Land
- Windows Registry Abuse
- ValleyRAT

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.002/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/eventvwr_uac_bypass.yml)*
