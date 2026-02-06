# Control Loading from World Writable Directory

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies instances of control.exe loading a .cpl or .inf file from a writable directory, which is related to CVE-2021-40444. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions mapped to the `Processes` node of the `Endpoint` data model. This activity is significant as it may indicate an attempt to exploit a known vulnerability, potentially leading to unauthorized code execution. If confirmed malicious, this could allow an attacker to gain control over the affected system, leading to further compromise.

## MITRE ATT&CK

- T1218.002

## Analytic Stories

- Microsoft MSHTML Remote Code Execution CVE-2021-40444
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

*Source: [Splunk Security Content](detections/endpoint/control_loading_from_world_writable_directory.yml)*
