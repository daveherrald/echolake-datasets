# SearchProtocolHost with no Command Line with Network

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects instances of searchprotocolhost.exe running without command line arguments but with an active network connection. This behavior is identified using Endpoint Detection and Response (EDR) telemetry, focusing on process execution and network traffic data. It is significant because searchprotocolhost.exe typically runs with specific command line arguments, and deviations from this norm can indicate malicious activity, such as Cobalt Strike usage. If confirmed malicious, this activity could allow attackers to establish network connections for command and control, potentially leading to data exfiltration or further system compromise.

## MITRE ATT&CK

- T1055

## Analytic Stories

- Graceful Wipe Out Attack
- Cobalt Strike
- Compromised Windows Host
- BlackByte Ransomware
- Cactus Ransomware
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 3

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon_searchprotocolhost.log


---

*Source: [Splunk Security Content](detections/endpoint/searchprotocolhost_with_no_command_line_with_network.yml)*
