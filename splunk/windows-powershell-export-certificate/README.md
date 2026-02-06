# Windows PowerShell Export Certificate

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the use of the PowerShell Cmdlet `export-certificate` by leveraging Script Block Logging. This activity is significant as it may indicate an adversary attempting to exfiltrate certificates from the local Certificate Store on a Windows endpoint. Monitoring this behavior is crucial because stolen certificates can be used to impersonate users, decrypt sensitive data, or facilitate further attacks. If confirmed malicious, this activity could lead to unauthorized access to encrypted communications and sensitive information, posing a severe security risk.

## MITRE ATT&CK

- T1552.004
- T1649

## Analytic Stories

- Windows Certificate Services

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1649/atomic_red_team/4104_export_certificate.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powershell_export_certificate.yml)*
