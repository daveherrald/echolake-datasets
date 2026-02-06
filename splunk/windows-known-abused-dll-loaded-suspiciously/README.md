# Windows Known Abused DLL Loaded Suspiciously

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic detects when DLLs with known abuse history are loaded from an unusual location. This activity may represent an attacker performing a DLL search order or sideload hijacking technique. These techniques are used to gain persistence as well as elevate privileges on the target system. This detection relies on Sysmon EID7 and is compatible with all Officla Sysmon TA versions.

## MITRE ATT&CK

- T1574.001

## Analytic Stories

- Windows Defense Evasion Tactics
- Living Off The Land

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1574.002/hijacklibs/hijacklibs_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_known_abused_dll_loaded_suspiciously.yml)*
