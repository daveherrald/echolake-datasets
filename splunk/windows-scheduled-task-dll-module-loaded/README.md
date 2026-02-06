# Windows Scheduled Task DLL Module Loaded

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects instances where the taskschd.dll is loaded by processes running in suspicious or writable directories. This activity is unusual, as legitimate processes that load taskschd.dll typically reside in protected system locations. Malware or threat actors may attempt to load this DLL from writable or non-standard directories to manipulate the Task Scheduler and execute malicious tasks. By identifying processes that load taskschd.dll in these unsafe locations, this detection helps security analysts flag potentially malicious activity and investigate further to prevent unauthorized system modifications.

## MITRE ATT&CK

- T1053

## Analytic Stories

- ValleyRAT

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053/taskschd_dll/taskschd_dll.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_scheduled_task_dll_module_loaded.yml)*
