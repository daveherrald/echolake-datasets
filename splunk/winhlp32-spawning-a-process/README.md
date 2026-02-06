# Winhlp32 Spawning a Process

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects winhlp32.exe spawning a child process that loads a file from appdata, programdata, or temp directories. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events. This activity is significant because winhlp32.exe has known vulnerabilities and can be exploited to execute malicious code. If confirmed malicious, an attacker could use this technique to execute arbitrary scripts, escalate privileges, or maintain persistence within the environment. Analysts should review parallel processes, module loads, and file modifications for further suspicious behavior.

## MITRE ATT&CK

- T1055

## Analytic Stories

- Remcos
- Compromised Windows Host

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/winhlp32_spawning_a_process.yml)*
