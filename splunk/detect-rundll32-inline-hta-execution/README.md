# Detect Rundll32 Inline HTA Execution

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of "rundll32.exe" with inline protocol handlers such as "JavaScript", "VBScript", and "About". This behavior is identified using Endpoint Detection and Response (EDR) telemetry, focusing on command-line arguments. This activity is significant as it is often associated with fileless malware or application whitelisting bypass techniques. If confirmed malicious, this could allow an attacker to execute arbitrary code, bypass security controls, and maintain persistence within the environment.

## MITRE ATT&CK

- T1218.005

## Analytic Stories

- Suspicious MSHTA Activity
- NOBELIUM Group
- Living Off The Land
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.005/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_rundll32_inline_hta_execution.yml)*
