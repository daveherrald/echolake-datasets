# Windows Scheduled Task Created Via XML

**Type:** Anomaly

**Author:** Teoderick Contreras, Nasreddine Bencherchali, Splunk

## Description

The following analytic detects the creation of scheduled tasks in Windows using schtasks.exe with the "XML" parameter.
This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions and process details.
This activity is significant as it is a common technique for establishing persistence or achieving privilege escalation, often used by malware like Trickbot and Winter-Vivern. While creating a scheduled task via XML may be legitimate, it can also be abused by attackers. If confirmed malicious, this could allow attackers to maintain access, execute additional payloads, and potentially lead to data theft or ransomware deployment.


## MITRE ATT&CK

- T1053.005

## Analytic Stories

- Winter Vivern
- Malicious Inno Setup Loader
- CISA AA23-347A
- Scheduled Tasks
- MoonPeak
- Lokibot

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/winter-vivern/scheduledtask/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_scheduled_task_created_via_xml.yml)*
