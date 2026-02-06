# Suspicious Rundll32 StartW

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies the execution of rundll32.exe with the DLL function names "Start" and "StartW," commonly associated with Cobalt Strike payloads. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions and process metadata. This activity is significant as it often indicates the presence of malicious payloads, such as Cobalt Strike, which can lead to unauthorized code execution. If confirmed malicious, this activity could allow attackers to inject shellcode, escalate privileges, and maintain persistence within the environment.

## MITRE ATT&CK

- T1218.011

## Analytic Stories

- Trickbot
- Suspicious Rundll32 Activity
- Cobalt Strike
- BlackByte Ransomware
- Graceful Wipe Out Attack
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.011/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_rundll32_startw.yml)*
