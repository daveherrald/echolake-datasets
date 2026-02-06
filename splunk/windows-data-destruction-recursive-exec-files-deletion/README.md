# Windows Data Destruction Recursive Exec Files Deletion

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic identifies a suspicious process that is recursively deleting executable files on a compromised host. It leverages Sysmon Event Codes 23 and 26 to detect this activity by monitoring for a high volume of deletions or overwrites of files with extensions like .exe, .sys, and .dll. This behavior is significant as it is commonly associated with destructive malware such as CaddyWiper, DoubleZero, and SwiftSlicer, which aim to make file recovery impossible. If confirmed malicious, this activity could lead to significant data loss and system instability, severely impacting business operations.

## MITRE ATT&CK

- T1485

## Analytic Stories

- Swift Slicer
- Data Destruction
- Handala Wiper
- Disk Wiper

## Data Sources

- Sysmon EventID 23
- Sysmon EventID 26

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/swift_slicer/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_data_destruction_recursive_exec_files_deletion.yml)*
