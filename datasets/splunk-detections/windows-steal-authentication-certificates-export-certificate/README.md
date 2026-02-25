# Windows Steal Authentication Certificates Export Certificate

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the use of the PowerShell cmdlet 'export-certificate' executed via the command line, indicating an attempt to export a certificate from the local Windows Certificate Store. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs and command-line arguments. Exporting certificates is significant as it may indicate credential theft or preparation for man-in-the-middle attacks. If confirmed malicious, this activity could allow an attacker to impersonate users, decrypt sensitive communications, or gain unauthorized access to systems and data.

## MITRE ATT&CK

- T1649

## Analytic Stories

- Windows Certificate Services

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1649/atomic_red_team/export_certificate_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_steal_authentication_certificates_export_certificate.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
