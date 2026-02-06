# Windows Access Token Manipulation Winlogon Duplicate Token Handle

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects a process attempting to access winlogon.exe to duplicate its handle. This is identified using Sysmon EventCode 10, focusing on processes targeting winlogon.exe with specific access rights. This activity is significant because it is a common technique used by adversaries to escalate privileges by leveraging the high privileges and security tokens associated with winlogon.exe. If confirmed malicious, this could allow an attacker to gain elevated privileges, potentially leading to full system compromise and unauthorized access to sensitive information.

## MITRE ATT&CK

- T1134.001

## Analytic Stories

- Brute Ratel C4

## Data Sources

- Sysmon EventID 10

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/brute_ratel/brute_duplicate_token/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_access_token_manipulation_winlogon_duplicate_token_handle.yml)*
