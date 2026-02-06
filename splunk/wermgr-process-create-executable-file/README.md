# Wermgr Process Create Executable File

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the wermgr.exe process creating an executable file. It leverages Sysmon EventCode 11 to identify instances where wermgr.exe generates a .exe file. This behavior is unusual because wermgr.exe is typically associated with error reporting, not file creation. Such activity is significant as it may indicate TrickBot malware, which injects code into wermgr.exe to execute malicious actions like downloading additional payloads. If confirmed malicious, this could lead to further malware infections, data exfiltration, or system compromise.

## MITRE ATT&CK

- T1027

## Analytic Stories

- Trickbot

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/infection/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/wermgr_process_create_executable_file.yml)*
