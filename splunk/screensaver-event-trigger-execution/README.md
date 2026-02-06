# Screensaver Event Trigger Execution

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications to the SCRNSAVE.EXE registry entry, indicating potential event trigger execution via screensaver settings for persistence or privilege escalation. It leverages registry activity data from the Endpoint data model to identify changes to the specified registry path. This activity is significant as it is a known technique used by APT groups and malware to maintain persistence or escalate privileges. If confirmed malicious, this could allow an attacker to execute arbitrary code with elevated privileges, leading to further system compromise and persistent access.

## MITRE ATT&CK

- T1546.002

## Analytic Stories

- Hermetic Wiper
- Windows Privilege Escalation
- Windows Persistence Techniques
- Windows Registry Abuse
- Data Destruction

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.002/scrnsave_reg/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/screensaver_event_trigger_execution.yml)*
