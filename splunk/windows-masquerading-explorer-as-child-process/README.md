# Windows Masquerading Explorer As Child Process

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies instances where explorer.exe is spawned by unusual parent processes such as cmd.exe, powershell.exe, or regsvr32.exe. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and parent process relationships. This activity is significant because explorer.exe is typically initiated by userinit.exe, and deviations from this norm can indicate code injection or process masquerading attempts by malware like Qakbot. If confirmed malicious, this behavior could allow attackers to execute arbitrary code, evade detection, and maintain persistence within the environment.

## MITRE ATT&CK

- T1574.001

## Analytic Stories

- Qakbot
- Compromised Windows Host
- Water Gamayun

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/qakbot/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_masquerading_explorer_as_child_process.yml)*
