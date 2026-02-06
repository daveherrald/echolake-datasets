# Windows Identify PowerShell Web Access IIS Pool

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This analytic detects and analyzes PowerShell Web Access (PSWA) usage in Windows environments. It tracks both connection attempts (EventID 4648) and successful logons (EventID 4624) associated with PSWA, providing a comprehensive view of access patterns. The analytic identifies PSWA's operational status, host servers, processes, and connection metrics. It highlights unique target accounts, domains accessed, and verifies logon types. This information is crucial for detecting potential misuse, such as lateral movement, brute force attempts, or unusual access patterns. By offering insights into PSWA activity, it enables security teams to quickly assess and investigate potential security incidents involving this powerful administrative tool.

## MITRE ATT&CK

- T1190

## Analytic Stories

- CISA AA24-241A

## Data Sources

- Windows Event Log Security 4648

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/pswa/4648_4624_pswa_pool.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_identify_powershell_web_access_iis_pool.yml)*
