# Detect mshta inline hta execution

**Type:** TTP

**Author:** Bhavin Patel, Michael Haag, Splunk

## Description

The following analytic detects the execution of "mshta.exe" with inline protocol handlers such as "JavaScript", "VBScript", and "About". It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line arguments and process details. This activity is significant because mshta.exe can be exploited to execute malicious scripts, potentially leading to unauthorized code execution. If confirmed malicious, this could allow an attacker to execute arbitrary code, escalate privileges, or establish persistence within the environment, posing a severe security risk.

## MITRE ATT&CK

- T1218.005

## Analytic Stories

- Compromised Windows Host
- Gozi Malware
- Living Off The Land
- Suspicious MSHTA Activity
- XWorm
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

*Source: [Splunk Security Content](detections/endpoint/detect_mshta_inline_hta_execution.yml)*
