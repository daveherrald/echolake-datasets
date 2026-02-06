# Windows Parent PID Spoofing with Explorer

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies a suspicious `explorer.exe` process with the `/root` command-line parameter. This detection leverages Endpoint Detection and Response (EDR) telemetry, focusing on process and command-line data. The presence of `/root` in `explorer.exe` is significant as it may indicate parent process spoofing, a technique used by malware to evade detection. If confirmed malicious, this activity could allow an attacker to operate undetected, potentially leading to unauthorized access, privilege escalation, or persistent threats within the environment.

## MITRE ATT&CK

- T1134.004

## Analytic Stories

- Compromised Windows Host
- Windows Defense Evasion Tactics

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1134/explorer_root_proc_cmdline/explorer_root.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_parent_pid_spoofing_with_explorer.yml)*
