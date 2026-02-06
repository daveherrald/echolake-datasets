# Detect Remote Access Software Usage Registry

**Type:** Anomaly

**Author:** Steven Dick

## Description

The following analytic detects when a known remote access software is added to common persistence locations on a device within the environment. Adversaries use these utilities to retain remote access capabilities to the environment. Utilities in the lookup include AnyDesk, GoToMyPC, LogMeIn, TeamViewer and much more. Review the lookup for the entire list and add any others.

## MITRE ATT&CK

- T1219

## Analytic Stories

- Insider Threat
- Command And Control
- Ransomware
- Gozi Malware
- CISA AA24-241A
- Remote Monitoring and Management Software
- Seashell Blizzard
- Cactus Ransomware
- Scattered Spider
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1219/screenconnect/screenconnect_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_remote_access_software_usage_registry.yml)*
