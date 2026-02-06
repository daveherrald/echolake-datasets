# MS Scripting Process Loading WMI Module

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the loading of WMI modules by Microsoft scripting processes like wscript.exe or cscript.exe. It leverages Sysmon EventCode 7 to identify instances where these scripting engines load specific WMI-related DLLs. This activity is significant because it can indicate the presence of malware, such as the FIN7 implant, which uses JavaScript to execute WMI queries for gathering host information to send to a C2 server. If confirmed malicious, this behavior could allow attackers to collect sensitive system information and maintain persistence within the environment.

## MITRE ATT&CK

- T1059.007

## Analytic Stories

- FIN7

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/fin7/fin7_js_2/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/ms_scripting_process_loading_wmi_module.yml)*
