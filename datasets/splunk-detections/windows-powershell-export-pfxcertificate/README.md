# Windows PowerShell Export PfxCertificate

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the use of the PowerShell cmdlet `export-pfxcertificate` by leveraging Script Block Logging. This activity is significant as it may indicate an adversary attempting to exfiltrate certificates from the Windows Certificate Store. Monitoring this behavior is crucial for identifying potential certificate theft, which can lead to unauthorized access and impersonation attacks. If confirmed malicious, this activity could allow attackers to compromise secure communications, authenticate as legitimate users, and escalate their privileges within the network.

## MITRE ATT&CK

- T1552.004
- T1649

## Analytic Stories

- Scattered Lapsus$ Hunters
- Windows Certificate Services
- Water Gamayun

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1649/atomic_red_team/4104_export_pfxcertificate.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powershell_export_pfxcertificate.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
