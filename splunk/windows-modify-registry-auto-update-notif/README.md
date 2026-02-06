# Windows Modify Registry Auto Update Notif

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects a suspicious modification to the Windows registry that changes the auto-update notification setting to "Notify before download." This detection leverages data from the Endpoint.Registry data model, focusing on specific registry paths and values. This activity is significant because it is a known technique used by adversaries, including malware like RedLine Stealer, to evade detection and potentially deploy additional payloads. If confirmed malicious, this modification could allow attackers to bypass security measures, maintain persistence, and exploit vulnerabilities on the target host.

## MITRE ATT&CK

- T1112

## Analytic Stories

- RedLine Stealer

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/redline/modify_registry/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_auto_update_notif.yml)*
