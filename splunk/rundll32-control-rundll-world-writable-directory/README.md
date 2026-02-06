# Rundll32 Control RunDLL World Writable Directory

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of rundll32.exe with the `Control_RunDLL` command, loading files from world-writable directories such as windows\temp, programdata, or appdata. This detection leverages Endpoint Detection and Response (EDR) telemetry, focusing on process command-line data and specific directory paths. This activity is significant as it may indicate an attempt to exploit CVE-2021-40444 or similar vulnerabilities, allowing attackers to execute arbitrary code. If confirmed malicious, this could lead to unauthorized code execution, privilege escalation, or persistent access within the environment.

## MITRE ATT&CK

- T1218.011

## Analytic Stories

- Microsoft MSHTML Remote Code Execution CVE-2021-40444
- Suspicious Rundll32 Activity
- Living Off The Land
- Compromised Windows Host

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.002/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/rundll32_control_rundll_world_writable_directory.yml)*
