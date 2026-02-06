# Suspicious Process DNS Query Known Abuse Web Services

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects a suspicious process making DNS queries to known, abused text-paste web services, VoIP, instant messaging, and digital distribution platforms. It leverages Sysmon EventID 22 logs to identify queries from processes like cmd.exe, powershell.exe, and others. This activity is significant as it may indicate an attempt to download malicious files, a common initial access technique. If confirmed malicious, this could lead to unauthorized code execution, data exfiltration, or further compromise of the target host.

## MITRE ATT&CK

- T1059.005

## Analytic Stories

- Snake Keylogger
- Meduza Stealer
- Malicious Inno Setup Loader
- Phemedrone Stealer
- Remcos
- Data Destruction
- PXA Stealer
- WhisperGate
- Cactus Ransomware
- Braodo Stealer
- RedLine Stealer

## Data Sources

- Sysmon EventID 22

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos_pastebin_download/sysmon.log


---

*Source: [Splunk Security Content](detections/network/suspicious_process_dns_query_known_abuse_web_services.yml)*
