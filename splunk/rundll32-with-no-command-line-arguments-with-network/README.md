# Rundll32 with no Command Line Arguments with Network

**Type:** TTP

**Author:** Steven Dick, Michael Haag, Splunk

## Description

The following analytic detects the execution of rundll32.exe without command line arguments, followed by a network connection. This behavior is identified using Endpoint Detection and Response (EDR) telemetry and network traffic data. It is significant because rundll32.exe typically requires arguments to function, and its absence is often associated with malicious activity, such as Cobalt Strike. If confirmed malicious, this activity could indicate an attempt to establish unauthorized network connections, potentially leading to data exfiltration or further compromise of the system.

## MITRE ATT&CK

- T1218.011

## Analytic Stories

- BlackSuit Ransomware
- Suspicious Rundll32 Activity
- Graceful Wipe Out Attack
- Cobalt Strike
- Compromised Windows Host
- PrintNightmare CVE-2021-34527
- BlackByte Ransomware
- Cactus Ransomware

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 3

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/rundll32_with_no_command_line_arguments_with_network.yml)*
