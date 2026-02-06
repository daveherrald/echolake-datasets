# Suspicious Rundll32 dllregisterserver

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of rundll32.exe with the DllRegisterServer command to load a DLL. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions and process details. This activity is significant as it may indicate an attempt to register a malicious DLL, which can be a method for code execution or persistence. If confirmed malicious, an attacker could gain unauthorized code execution, escalate privileges, or maintain persistence within the environment, posing a severe security risk.

## MITRE ATT&CK

- T1218.011

## Analytic Stories

- Suspicious Rundll32 Activity
- Living Off The Land
- IcedID

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.011/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_rundll32_dllregisterserver.yml)*
