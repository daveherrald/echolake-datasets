# Windows Boot or Logon Autostart Execution In Startup Folder

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the creation of files in the Windows %startup% folder, a common persistence technique. It leverages the Endpoint.Filesystem data model to identify file creation events in this specific directory. This activity is significant because adversaries often use the startup folder to ensure their malicious code executes automatically upon system boot or user logon. If confirmed malicious, this could allow attackers to maintain persistence on the host, potentially leading to further system compromise and unauthorized access to sensitive information.

## MITRE ATT&CK

- T1547.001

## Analytic Stories

- XWorm
- Chaos Ransomware
- NjRAT
- Crypto Stealer
- Gozi Malware
- Quasar RAT
- RedLine Stealer
- Interlock Ransomware
- APT37 Rustonotto and FadeStealer
- PromptFlux

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/chaos_ransomware/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_boot_or_logon_autostart_execution_in_startup_folder.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
