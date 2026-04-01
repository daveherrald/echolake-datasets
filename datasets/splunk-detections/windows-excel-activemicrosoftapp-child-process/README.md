# Windows Excel ActiveMicrosoftApp Child Process

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying the execution of the ActiveMicrosoftApp process as a child of Microsoft Excel. Under normal conditions, Excel primarily spawns internal Office-related processes, and the creation of ActiveMicrosoftApp is uncommon in day-to-day business workflows. Adversaries may abuse this behavior to blend malicious activity within trusted applications, execute unauthorized code, or bypass application control mechanisms. This technique aligns with common tradecraft where Office applications are leveraged as initial access or execution vectors due to their prevalence in enterprise environments. Detecting this relationship helps defenders spot suspicious child processes that may indicate malware execution, persistence mechanisms, or attempts to establish command-and-control. Security teams should investigate the parent Excel process, the context of the ActiveMicrosoftApp execution, and any subsequent network or file activity. While certain legitimate Office features could trigger this process in specific environments, its occurrence generally warrants further scrutiny to validate intent and rule out compromise.

## MITRE ATT&CK

- T1021.003

## Analytic Stories

- PathWiper

## Data Sources

- Sysmon EventID 1

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.003/excel_activemicrosoftapp/sysmon_winprojexe.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_excel_activemicrosoftapp_child_process.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
