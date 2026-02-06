# Windows Credentials from Web Browsers Saved in TEMP Folder

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the creation of files containing passwords, cookies, and saved login account information by the Braodo stealer malware in temporary folders. Braodo often collects these credentials from browsers and applications, storing them in temp directories before exfiltration. This detection focuses on monitoring for the creation of files with patterns or formats commonly associated with stolen credentials. By identifying these activities, security teams can take needed action to prevent sensitive login data from being leaked, reducing the risk of unauthorized access to user accounts and systems.

## MITRE ATT&CK

- T1555.003

## Analytic Stories

- Braodo Stealer
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1555.003/browser_credential_info_temp/braodo_browser_info.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_credentials_from_web_browsers_saved_in_temp_folder.yml)*
