# CSC Net On The Fly Compilation

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the use of the .NET compiler csc.exe for on-the-fly compilation of potentially malicious .NET code. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on specific command-line patterns associated with csc.exe. This activity is significant because adversaries and malware often use this technique to evade detection by compiling malicious code at runtime. If confirmed malicious, this could allow attackers to execute arbitrary code, potentially leading to system compromise, data exfiltration, or further lateral movement within the network.

## MITRE ATT&CK

- T1027.004

## Analytic Stories

- Windows Defense Evasion Tactics

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/vilsel/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/csc_net_on_the_fly_compilation.yml)*
