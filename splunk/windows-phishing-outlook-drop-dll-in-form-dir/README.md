# Windows Phishing Outlook Drop Dll In FORM Dir

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the creation of a DLL file by an outlook.exe process in the AppData\Local\Microsoft\FORMS directory. This detection leverages data from the Endpoint.Processes and Endpoint.Filesystem datamodels, focusing on process and file creation events. This activity is significant as it may indicate an attempt to exploit CVE-2024-21378, where a custom MAPI form loads a potentially malicious DLL. If confirmed malicious, this could allow an attacker to execute arbitrary code, leading to further system compromise or data exfiltration.

## MITRE ATT&CK

- T1566

## Analytic Stories

- Outlook RCE CVE-2024-21378

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566/outlook_dropped_dll/outlook_phishing_form_dll.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_phishing_outlook_drop_dll_in_form_dir.yml)*
