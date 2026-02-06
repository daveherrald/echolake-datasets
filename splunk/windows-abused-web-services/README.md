# Windows Abused Web Services

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects a suspicious process making DNS queries to known, abused web services such as text-paste sites, VoIP, secure tunneling, instant messaging, and digital distribution platforms. This detection leverages Sysmon logs with Event ID 22, focusing on specific query names. This activity is significant as it may indicate an adversary attempting to download malicious files, a common initial access technique. If confirmed malicious, this could lead to unauthorized code execution, data exfiltration, or further compromise of the target host.

## MITRE ATT&CK

- T1102

## Analytic Stories

- NjRAT
- CISA AA24-241A
- Malicious Inno Setup Loader

## Data Sources

- Sysmon EventID 22

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1102/njrat_ngrok_connection/ngrok.log


---

*Source: [Splunk Security Content](detections/network/windows_abused_web_services.yml)*
