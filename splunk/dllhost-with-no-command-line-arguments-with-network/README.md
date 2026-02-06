# DLLHost with no Command Line Arguments with Network

**Type:** TTP

**Author:** Steven Dick, Michael Haag, Splunk

## Description

The following analytic detects instances of DLLHost.exe running without
command line arguments while establishing a network connection.
This behavior is identified using Endpoint Detection and Response (EDR) telemetry,
focusing on process execution and network activity data.
It is significant because DLLHost.exe typically runs with specific arguments,
and its absence can indicate malicious activity, such as Cobalt Strike usage.
If confirmed malicious, this activity could allow attackers to execute code,
move laterally, or exfiltrate data, posing a severe threat to the network's security.


## MITRE ATT&CK

- T1055

## Analytic Stories

- BlackByte Ransomware
- Cobalt Strike
- Graceful Wipe Out Attack
- Cactus Ransomware
- Storm-2460 CLFS Zero Day Exploitation
- Earth Alux

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 3

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon_dllhost.log


---

*Source: [Splunk Security Content](detections/endpoint/dllhost_with_no_command_line_arguments_with_network.yml)*
