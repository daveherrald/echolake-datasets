# Windows LOLBAS Executed As Renamed File

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic identifies a LOLBAS process being executed where it's process name does not match it's original file name attribute. Processes that have been renamed and executed may be an indicator that an adversary is attempting to evade defenses or execute malicious code. The LOLBAS project documents Windows native binaries that can be abused by threat actors to perform tasks like executing malicious code.

## MITRE ATT&CK

- T1036.003
- T1218.011

## Analytic Stories

- Living Off The Land
- Masquerading - Rename System Utilities
- Windows Defense Evasion Tactics
- Water Gamayun

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036/cmd_lolbas_usage/cmd_lolbas_usage.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_lolbas_executed_as_renamed_file.yml)*
