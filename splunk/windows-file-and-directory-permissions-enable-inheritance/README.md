# Windows File and Directory Permissions Enable Inheritance

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the enabling of permission inheritance using ICACLS. This analytic identifies instances where ICACLS commands are used to enable permission inheritance on files or directories. The /inheritance:e flag, which restores inherited permissions from a parent directory, is monitored to detect changes that might reapply broader access control settings. Enabling inheritance can indicate legitimate administrative actions but may also signal attempts to override restrictive custom permissions, potentially exposing sensitive files to unauthorized access.

## MITRE ATT&CK

- T1222.001

## Analytic Stories

- Crypto Stealer
- NetSupport RMM Tool Abuse

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1222.001/icacls_inheritance/icacls_process_1.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_file_and_directory_permissions_enable_inheritance.yml)*
