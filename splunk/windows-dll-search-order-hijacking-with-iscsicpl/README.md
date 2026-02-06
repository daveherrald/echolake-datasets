# Windows DLL Search Order Hijacking with iscsicpl

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects DLL search order hijacking involving iscsicpl.exe. It identifies when iscsicpl.exe loads a malicious DLL from a new path, triggering the payload execution. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on child processes spawned by iscsicpl.exe. This activity is significant as it indicates a potential attempt to execute unauthorized code via DLL hijacking. If confirmed malicious, this could allow an attacker to execute arbitrary code, escalate privileges, or maintain persistence within the environment.

## MITRE ATT&CK

- T1574.001

## Analytic Stories

- Living Off The Land
- Compromised Windows Host
- Windows Defense Evasion Tactics

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1574.001/iscsicpl/iscsicpl-windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_dll_search_order_hijacking_with_iscsicpl.yml)*
