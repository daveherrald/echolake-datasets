# Windows User Execution Malicious URL Shortcut File

**Type:** Anomaly

**Author:** Teoderick Contreras, Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting the creation URL shortcut files, often used by malware like CHAOS ransomware. It leverages the Endpoint.Filesystem datamodel to identify ".url" files created outside common directories, such as "Program Files". This activity can be significant as ".URL" files can be used as mean to trick the user into visiting certain websites unknowingly, or when placed in certain locations such as "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\", it may allow the execution of malicious code upon system reboot. If confirmed malicious, this could allow an attacker to achieve persistence and execute harmful payloads, potentially leading to further system compromise and data loss.

## MITRE ATT&CK

- T1204.002

## Analytic Stories

- XWorm
- Chaos Ransomware
- NjRAT
- Quasar RAT
- Snake Keylogger
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/chaos_ransomware/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_user_execution_malicious_url_shortcut_file.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
