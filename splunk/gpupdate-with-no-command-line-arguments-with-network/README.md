# GPUpdate with no Command Line Arguments with Network

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of gpupdate.exe without command line arguments and with an active network connection. This behavior is identified using Endpoint Detection and Response (EDR) telemetry, focusing on process execution and network traffic data. It is significant because gpupdate.exe typically runs with specific arguments, and its execution without them, especially with network activity, is often associated with malicious software like Cobalt Strike. If confirmed malicious, this activity could indicate an attacker leveraging gpupdate.exe for lateral movement, command and control, or other nefarious purposes, potentially leading to system compromise.

## MITRE ATT&CK

- T1055

## Analytic Stories

- Graceful Wipe Out Attack
- Cobalt Strike
- Compromised Windows Host
- BlackByte Ransomware
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 3

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/gpupdate_with_no_command_line_arguments_with_network.yml)*
