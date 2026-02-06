# Detect Regasm Spawning a Process

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects regasm.exe spawning a child process. This behavior is identified using data from Endpoint Detection and Response (EDR) agents, focusing on process creation events where regasm.exe is the parent process. This activity is significant because regasm.exe spawning a process is rare and can indicate an attempt to bypass application control mechanisms. If confirmed malicious, this could allow an attacker to execute arbitrary code, potentially leading to privilege escalation or persistent access within the environment. Immediate investigation is recommended to determine the legitimacy of the spawned process and any associated activities.

## MITRE ATT&CK

- T1218.009

## Analytic Stories

- Suspicious Regsvcs Regasm Activity
- Living Off The Land
- Handala Wiper
- Compromised Windows Host
- DarkGate Malware
- Snake Keylogger

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.009/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_regasm_spawning_a_process.yml)*
