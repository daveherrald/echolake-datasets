# Windows App Layer Protocol Qakbot NamedPipe

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects a suspicious process creating or connecting to a potential Qakbot named pipe. It leverages Sysmon EventCodes 17 and 18, focusing on specific processes known to be abused by Qakbot and identifying randomly generated named pipes in GUID form. This activity is significant as Qakbot malware uses named pipes for inter-process communication after code injection, facilitating data theft. If confirmed malicious, this behavior could indicate a Qakbot infection, leading to unauthorized data access and potential exfiltration from the compromised host.

## MITRE ATT&CK

- T1071

## Analytic Stories

- Qakbot

## Data Sources

- Sysmon EventID 17
- Sysmon EventID 18

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/qakbot/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_app_layer_protocol_qakbot_namedpipe.yml)*
