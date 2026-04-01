# Windows RunMRU Command Execution

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Michael Haag, Splunk

## Description

This dataset contains sample data for detecting modifications to the Windows RunMRU registry key, which stores a history of commands executed through the Run dialog box (Windows+R). It leverages Endpoint Detection and Response (EDR) telemetry to monitor registry events targeting this key. This activity is significant as malware often uses the Run dialog to execute malicious commands while attempting to appear legitimate. If confirmed malicious, this could indicate an attacker using indirect command execution techniques for defense evasion or persistence. The detection excludes MRUList value changes to focus on actual command entries.

## MITRE ATT&CK

- T1202

## Analytic Stories

- Lumma Stealer
- Fake CAPTCHA Campaigns

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1202/atomic_red_team/windows-sysmon_runmru.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_runmru_command_execution.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
