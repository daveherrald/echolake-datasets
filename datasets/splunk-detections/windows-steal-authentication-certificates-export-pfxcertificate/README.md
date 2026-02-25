# Windows Steal Authentication Certificates Export PfxCertificate

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the use of the PowerShell cmdlet `export-pfxcertificate` on the command line, indicating an attempt to export a certificate from the local Windows Certificate Store. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs and command-line arguments. This activity is significant as it may indicate an attempt to exfiltrate authentication certificates, which can be used to impersonate users or decrypt sensitive data. If confirmed malicious, this could lead to unauthorized access and potential data breaches.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1649/atomic_red_team/export_pfxcertificate_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_steal_authentication_certificates_export_pfxcertificate.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
