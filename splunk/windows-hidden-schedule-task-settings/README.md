# Windows Hidden Schedule Task Settings

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the creation of hidden scheduled tasks on Windows systems, which are not visible in the UI. It leverages Windows Security EventCode 4698 to identify tasks where the 'Hidden' setting is enabled. This behavior is significant as it may indicate malware activity, such as Industroyer2, or the use of living-off-the-land binaries (LOLBINs) to download additional payloads. If confirmed malicious, this activity could allow attackers to execute code stealthily, maintain persistence, or further compromise the system by downloading additional malicious payloads.

## MITRE ATT&CK

- T1053

## Analytic Stories

- CISA AA22-257A
- Active Directory Discovery
- Malicious Inno Setup Loader
- Compromised Windows Host
- Data Destruction
- Industroyer2
- Cactus Ransomware
- Scheduled Tasks
- Hellcat Ransomware

## Data Sources

- Windows Event Log Security 4698

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053/hidden_schedule_task/inno_schtask.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_hidden_schedule_task_settings.yml)*
