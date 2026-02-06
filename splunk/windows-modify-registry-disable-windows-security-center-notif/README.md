# Windows Modify Registry Disable Windows Security Center Notif

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications to the Windows registry aimed at disabling Windows Security Center notifications. It leverages data from the Endpoint.Registry datamodel, specifically monitoring changes to the registry path "*\\Windows\\CurrentVersion\\ImmersiveShell\\UseActionCenterExperience*" with a value of "0x00000000". This activity is significant as it can indicate an attempt by adversaries or malware, such as Azorult, to evade defenses by suppressing critical update notifications. If confirmed malicious, this could allow attackers to persist undetected, potentially leading to further exploitation and compromise of the host system.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Azorult
- CISA AA23-347A

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_disable_windows_security_center_notif.yml)*
