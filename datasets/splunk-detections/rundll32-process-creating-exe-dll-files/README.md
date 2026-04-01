# Rundll32 Process Creating Exe Dll Files

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a rundll32 process creating executable (.exe) or dynamic link library (.dll) files. It leverages Sysmon EventCode 11 to identify instances where rundll32.exe generates these file types. This activity is significant because rundll32 is often exploited by malware, such as IcedID, to drop malicious payloads in directories like Temp, AppData, or ProgramData. If confirmed malicious, this behavior could allow an attacker to execute arbitrary code, establish persistence, or escalate privileges within the environment.

## MITRE ATT&CK

- T1218.011

## Analytic Stories

- IcedID
- Living Off The Land

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/inf_icedid/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/rundll32_process_creating_exe_dll_files.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
