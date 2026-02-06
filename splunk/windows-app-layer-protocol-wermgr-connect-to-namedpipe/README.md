# Windows App Layer Protocol Wermgr Connect To NamedPipe

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the wermgr.exe process creating or connecting to a named pipe. It leverages Sysmon EventCodes 17 and 18 to identify these actions. This activity is significant because wermgr.exe, a legitimate Windows OS Problem Reporting application, is often abused by malware such as Trickbot and Qakbot to execute malicious code. If confirmed malicious, this behavior could indicate that an attacker has injected code into wermgr.exe, potentially allowing them to communicate covertly, escalate privileges, or persist within the environment.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/qakbot/qbot_wermgr2/sysmon_wermgr2.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_app_layer_protocol_wermgr_connect_to_namedpipe.yml)*
