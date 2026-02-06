# Wermgr Process Connecting To IP Check Web Services

**Type:** TTP

**Author:** Teoderick Contreras, Mauricio Velazco, Splunk

## Description

The following analytic detects the wermgr.exe process attempting to connect to known IP check web services. It leverages Sysmon EventCode 22 to identify DNS queries made by wermgr.exe to specific IP check services. This activity is significant because wermgr.exe is typically used for Windows error reporting, and its connection to these services may indicate malicious code injection, often associated with malware like Trickbot. If confirmed malicious, this behavior could allow attackers to recon the infected machine's IP address, aiding in further exploitation and evasion tactics.

## MITRE ATT&CK

- T1590.005

## Analytic Stories

- Trickbot

## Data Sources

- Sysmon EventID 22

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/infection/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/network/wermgr_process_connecting_to_ip_check_web_services.yml)*
