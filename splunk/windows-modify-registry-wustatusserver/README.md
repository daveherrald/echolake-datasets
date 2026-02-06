# Windows Modify Registry wuStatusServer

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies suspicious modifications to the Windows Update configuration registry, specifically targeting the WUStatusServer key. It leverages data from the Endpoint datamodel to detect changes in the registry path associated with Windows Update settings. This activity is significant as it is commonly used by adversaries, including malware like RedLine Stealer, to bypass detection and deploy additional payloads. If confirmed malicious, this modification could allow attackers to evade defenses, potentially leading to further system compromise and persistent unauthorized access.

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

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_wustatusserver.yml)*
