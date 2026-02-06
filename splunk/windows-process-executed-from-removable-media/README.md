# Windows Process Executed From Removable Media

**Type:** Anomaly

**Author:** Steven Dick

## Description

This analytic is used to identify when a removable media device is attached to a machine and then a process is executed from the same drive letter assigned to the removable media device. Adversaries and Insider Threats may use removable media devices for several malicious activities, including initial access, execution, and exfiltration.

## MITRE ATT&CK

- T1200
- T1025
- T1091

## Analytic Stories

- Data Protection
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1200/sysmon_usb_use_execution/sysmon_usb_use_execution.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_process_executed_from_removable_media.yml)*
