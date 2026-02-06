# Windows Process Injection With Public Source Path

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects a process from a non-standard file path on Windows attempting to create a remote thread in another process. This is identified using Sysmon EventCode 8, focusing on processes not originating from typical system directories. This behavior is significant as it often indicates process injection, a technique used by adversaries to evade detection or escalate privileges. If confirmed malicious, this activity could allow an attacker to execute arbitrary code within another process, potentially leading to unauthorized actions and further compromise of the system.

## MITRE ATT&CK

- T1055.002

## Analytic Stories

- Brute Ratel C4
- Earth Alux

## Data Sources

- Sysmon EventID 8

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/brute_ratel/create_remote_thread/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_process_injection_with_public_source_path.yml)*
