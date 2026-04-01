# Windows Powershell Logoff User via Quser

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the process of logging off a user through the use of the quser and logoff commands. By monitoring for these commands, the analytic identifies actions where a user session is forcibly terminated, which could be part of an administrative task or a potentially unauthorized access attempt. This detection helps identify potential misuse or malicious activity where a user’s access is revoked without proper authorization, providing insight into potential security incidents involving account management or session manipulation.

## MITRE ATT&CK

- T1059.001
- T1531

## Analytic Stories

- Crypto Stealer

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1531/log_off_user/pwh_quser_logoff.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powershell_logoff_user_via_quser.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
