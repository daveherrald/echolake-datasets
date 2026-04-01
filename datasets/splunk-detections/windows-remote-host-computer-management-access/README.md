# Windows Remote Host Computer Management Access

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the use of mmc.exe to launch Computer Management (compmgmt.msc) and connect to a remote machine. This technique allows administrators to access system management tools, including Event Viewer, Services, Shared Folders, and Local Users & Groups, without initiating a full remote desktop session. While commonly used for legitimate administrative purposes, adversaries may leverage this method for remote reconnaissance, privilege escalation, or persistence. Monitoring the execution of mmc.exe with the /computer:{hostname/ip} argument can help detect unauthorized system administration attempts or lateral movement within a network.

## MITRE ATT&CK

- T1021.006

## Analytic Stories

- Medusa Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.006/compmgtm_access/compmgmt_load.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_remote_host_computer_management_access.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
