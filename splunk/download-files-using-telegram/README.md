# Download Files Using Telegram

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects suspicious file downloads by the Telegram application on a Windows system. It leverages Sysmon EventCode 15 to identify instances where Telegram.exe creates files with a Zone.Identifier, indicating a download. This activity is significant as it may indicate an adversary using Telegram to download malicious tools, such as network scanners, for further exploitation. If confirmed malicious, this behavior could lead to network mapping, lateral movement, and potential compromise of additional systems within the network.

## MITRE ATT&CK

- T1105

## Analytic Stories

- Phemedrone Stealer
- Crypto Stealer
- Snake Keylogger
- XMRig
- Water Gamayun
- 0bj3ctivity Stealer

## Data Sources

- Sysmon EventID 15

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/minergate/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/download_files_using_telegram.yml)*
