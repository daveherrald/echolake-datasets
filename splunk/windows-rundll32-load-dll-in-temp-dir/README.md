# Windows Rundll32 Load DLL in Temp Dir

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This detection identifies instances where rundll32.exe is used to load a DLL from a temporary directory, such as C:\Users\<User>\AppData\Local\Temp\ or C:\Windows\Temp\. While rundll32.exe is a legitimate Windows utility used to execute functions exported from DLLs, its use to load libraries from temporary locations is highly suspicious. These directories are commonly used by malware and red team tools to stage payloads or execute code in-memory without writing it to more persistent locations. This behavior often indicates defense evasion, initial access, or privilege escalation, especially when the DLL is unsigned, recently written, or executed shortly after download. In normal user workflows, DLLs are not typically loaded from Temp paths, making this a high-fidelity indicator of potentially malicious activity. Monitoring this pattern is essential for detecting threats that attempt to blend in with native system processes while bypassing traditional application controls.

## MITRE ATT&CK

- T1218.011

## Analytic Stories

- Interlock Rat

## Data Sources

- Sysmon EventID 1

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.011/rundll32_dll_in_temp/rundll32_tmp.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_rundll32_load_dll_in_temp_dir.yml)*
