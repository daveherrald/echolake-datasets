# Windows Registry Payload Injection

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic detects suspiciously long data written to the Windows registry, a behavior often linked to fileless malware or persistence techniques. It leverages Endpoint Detection and Response (EDR) telemetry, focusing on registry events with data lengths exceeding 512 characters. This activity is significant as it can indicate an attempt to evade traditional file-based defenses, making it crucial for SOC monitoring. If confirmed malicious, this technique could allow attackers to maintain persistence, execute code, or manipulate system configurations without leaving a conventional file footprint.

## MITRE ATT&CK

- T1027.011

## Analytic Stories

- Unusual Processes

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/gootloader/partial_ttps/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_registry_payload_injection.yml)*
