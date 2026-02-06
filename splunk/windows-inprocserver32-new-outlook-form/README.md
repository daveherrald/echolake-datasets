# Windows InProcServer32 New Outlook Form

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the creation or modification of registry keys associated with new Outlook form installations, potentially indicating exploitation of CVE-2024-21378. It leverages data from the Endpoint.Registry datamodel, focusing on registry paths involving InProcServer32 keys linked to Outlook forms. This activity is significant as it may signify an attempt to achieve authenticated remote code execution via malicious form objects. If confirmed malicious, this could allow an attacker to create arbitrary files and registry keys, leading to remote code execution and potential full system compromise.

## MITRE ATT&CK

- T1566
- T1112

## Analytic Stories

- Outlook RCE CVE-2024-21378

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566/cve-2024-21378/inprocserver32_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_inprocserver32_new_outlook_form.yml)*
