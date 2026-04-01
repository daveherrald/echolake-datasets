# Windows Modify Registry DisableRemoteDesktopAntiAlias

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting modifications to the Windows registry key "DisableRemoteDesktopAntiAlias" with a value set to 0x00000001. This detection leverages data from the Endpoint datamodel, specifically monitoring changes in the Registry node. This activity is significant as it may indicate the presence of DarkGate malware, which alters this registry setting to enhance its remote desktop capabilities. If confirmed malicious, this modification could allow an attacker to maintain persistence and control over the compromised host, potentially leading to further exploitation and data exfiltration.

## MITRE ATT&CK

- T1112

## Analytic Stories

- DarkGate Malware

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/DisableRemoteDesktopAntiAlias/disable_remote_alias.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_disableremotedesktopantialias.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
