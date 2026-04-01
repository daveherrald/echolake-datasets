# Suspicious Scheduled Task from Public Directory

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying the creation of scheduled tasks that execute binaries or scripts from public directories, such as users\public, \programdata\, or \windows\temp, using schtasks.exe with the /create command. It leverages Sysmon Event ID 1 data to detect this behavior. This activity is significant because it often indicates an attempt to maintain persistence or execute malicious scripts, which are common tactics in malware deployment. If confirmed as malicious, this could lead to data compromise, unauthorized access, and potential lateral movement within the network.

## MITRE ATT&CK

- T1053.005

## Analytic Stories

- XWorm
- Medusa Ransomware
- CISA AA23-347A
- Azorult
- Scheduled Tasks
- Living Off The Land
- Ransomware
- Crypto Stealer
- Salt Typhoon
- Quasar RAT
- DarkCrystal RAT
- Ryuk Ransomware
- CISA AA24-241A
- Malicious Inno Setup Loader
- Windows Persistence Techniques
- MoonPeak
- China-Nexus Threat Activity
- Scattered Spider
- APT37 Rustonotto and FadeStealer
- Lokibot
- NetSupport RMM Tool Abuse

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/schtasks/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_scheduled_task_from_public_directory.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
