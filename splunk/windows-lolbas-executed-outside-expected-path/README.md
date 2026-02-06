# Windows LOLBAS Executed Outside Expected Path

**Type:** Anomaly

**Author:** Steven Dick

## Description

The following analytic identifies a LOLBAS process being executed outside of it's expected location.
Processes being executed outside of expected locations may be an indicator that an adversary is attempting to evade defenses or execute malicious code.
The LOLBAS project documents Windows native binaries that can be abused by threat actors to perform tasks like executing malicious code.


## MITRE ATT&CK

- T1036.005
- T1218.011

## Analytic Stories

- Living Off The Land
- Masquerading - Rename System Utilities
- Windows Defense Evasion Tactics

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036/cmd_lolbas_usage/cmd_lolbas_usage.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_lolbas_executed_outside_expected_path.yml)*
