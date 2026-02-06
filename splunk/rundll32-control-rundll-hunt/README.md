# Rundll32 Control RunDLL Hunt

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies instances of rundll32.exe executing with `Control_RunDLL` in the command line, which is indicative of loading a .cpl or other file types. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs and command-line arguments. This activity is significant as rundll32.exe can be exploited to execute malicious Control Panel Item files, potentially linked to CVE-2021-40444. If confirmed malicious, this could allow attackers to execute arbitrary code, escalate privileges, or maintain persistence within the environment.

## MITRE ATT&CK

- T1218.011

## Analytic Stories

- Suspicious Rundll32 Activity
- Microsoft MSHTML Remote Code Execution CVE-2021-40444
- Living Off The Land

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.002/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/rundll32_control_rundll_hunt.yml)*
