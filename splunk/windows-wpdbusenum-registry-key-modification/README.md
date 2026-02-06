# Windows WPDBusEnum Registry Key Modification

**Type:** Anomaly

**Author:** Steven Dick

## Description

This analytic is used to identify when a USB removable media device is attached to a Windows host. In this scenario we are querying the Endpoint Registry data model to look for modifications to the Windows Portable Device keys HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices\ or HKLM\System\CurrentControlSet\Enum\SWD\WPDBUSENUM\ . Adversaries and Insider Threats may use removable media devices for several malicious activities, including initial access, execution, and exfiltration.

## MITRE ATT&CK

- T1200
- T1025
- T1091

## Analytic Stories

- Data Protection
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 12
- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1200/sysmon_usb_use_execution/sysmon_usb_use_execution.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_wpdbusenum_registry_key_modification.yml)*
