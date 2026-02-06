# Suspicious Rundll32 no Command Line Arguments

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of rundll32.exe without any command line arguments. This behavior is identified using Endpoint Detection and Response (EDR) telemetry, focusing on process execution logs. It is significant because rundll32.exe typically requires command line arguments to function properly, and its absence is often associated with malicious activities, such as those performed by Cobalt Strike. If confirmed malicious, this activity could indicate an attempt to execute arbitrary code, potentially leading to credential dumping, unauthorized file writes, or other malicious actions.

## MITRE ATT&CK

- T1218.011

## Analytic Stories

- Suspicious Rundll32 Activity
- Cobalt Strike
- BlackByte Ransomware
- PrintNightmare CVE-2021-34527
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

*Source: [Splunk Security Content](detections/endpoint/suspicious_rundll32_no_command_line_arguments.yml)*
