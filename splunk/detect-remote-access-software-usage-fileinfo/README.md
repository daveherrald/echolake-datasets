# Detect Remote Access Software Usage FileInfo

**Type:** Anomaly

**Author:** Steven Dick

## Description

The following analytic detects the execution of processes with file or code signing attributes from known remote access software within the environment. It leverages Sysmon EventCode 1 data and cross-references a lookup table of remote access utilities such as AnyDesk, GoToMyPC, LogMeIn, and TeamViewer. This activity is significant as adversaries often use these tools to maintain unauthorized remote access. If confirmed malicious, this could allow attackers to persist in the environment, potentially leading to data exfiltration or further compromise of the network.

## MITRE ATT&CK

- T1219

## Analytic Stories

- Insider Threat
- Command And Control
- Ransomware
- Gozi Malware
- Remote Monitoring and Management Software
- Cactus Ransomware
- Seashell Blizzard
- Scattered Spider
- Interlock Ransomware
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 1

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1219/screenconnect/screenconnect_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_remote_access_software_usage_fileinfo.yml)*
