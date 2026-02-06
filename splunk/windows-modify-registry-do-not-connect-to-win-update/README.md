# Windows Modify Registry Do Not Connect To Win Update

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects a suspicious modification to the Windows registry that disables automatic updates. It leverages data from the Endpoint datamodel, specifically monitoring changes to the registry path "*\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\DoNotConnectToWindowsUpdateInternetLocations" with a value of "0x00000001". This activity is significant as it can be used by adversaries, including malware like RedLine Stealer, to evade detection and prevent the system from receiving critical updates. If confirmed malicious, this could allow attackers to exploit vulnerabilities, persist in the environment, and potentially deploy additional payloads.

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

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_do_not_connect_to_win_update.yml)*
