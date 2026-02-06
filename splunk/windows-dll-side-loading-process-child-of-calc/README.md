# Windows DLL Side-Loading Process Child Of Calc

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies suspicious child processes spawned by calc.exe, indicative of DLL side-loading techniques. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process GUIDs, names, and parent processes. This activity is significant as it is commonly associated with Qakbot malware, which uses calc.exe to load malicious DLLs via regsvr32.exe. If confirmed malicious, this behavior could allow attackers to execute arbitrary code, maintain persistence, and escalate privileges, posing a severe threat to the environment.

## MITRE ATT&CK

- T1574.001

## Analytic Stories

- Qakbot
- Earth Alux

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/qakbot/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_dll_side_loading_process_child_of_calc.yml)*
