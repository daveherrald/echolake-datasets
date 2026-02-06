# Suspicious DLLHost no Command Line Arguments

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects instances of DLLHost.exe executing without command line arguments. This behavior is unusual and often associated with malicious activities, such as those performed by Cobalt Strike. The detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs. This activity is significant because DLLHost.exe typically requires arguments to function correctly, and its absence may indicate an attempt to evade detection. If confirmed malicious, this could lead to unauthorized actions like credential dumping or file manipulation, posing a severe threat to the environment.

## MITRE ATT&CK

- T1055

## Analytic Stories

- BlackByte Ransomware
- Cobalt Strike
- Graceful Wipe Out Attack
- Cactus Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_dllhost_no_command_line_arguments.yml)*
