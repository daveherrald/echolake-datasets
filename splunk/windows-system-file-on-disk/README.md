# Windows System File on Disk

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the creation of new .sys files on disk. It leverages the Endpoint.Filesystem data model to identify and log instances where .sys files are written to the filesystem. This activity is significant because .sys files are often used as kernel mode drivers, and their unauthorized creation can indicate malicious activity such as rootkit installation. If confirmed malicious, this could allow an attacker to gain kernel-level access, leading to full system compromise, persistent control, and the ability to bypass security mechanisms.

## MITRE ATT&CK

- T1068

## Analytic Stories

- CISA AA22-264A
- Windows Drivers
- Crypto Stealer

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1068/drivers/sysmon_sys_filemod.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_system_file_on_disk.yml)*
