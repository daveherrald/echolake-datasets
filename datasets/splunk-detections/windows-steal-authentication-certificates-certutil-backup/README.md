# Windows Steal Authentication Certificates CertUtil Backup

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting CertUtil.exe performing a backup of the Certificate Store. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on specific command-line executions involving CertUtil with backup parameters. This activity is significant because it may indicate an attempt to steal authentication certificates, which are critical for secure communications. If confirmed malicious, an attacker could use the stolen certificates to impersonate users, decrypt sensitive data, or gain unauthorized access to systems, leading to severe security breaches.

## MITRE ATT&CK

- T1649

## Analytic Stories

- Windows Certificate Services
- Storm-2460 CLFS Zero Day Exploitation

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1649/atomic_red_team/backupdb_certutil_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_steal_authentication_certificates_certutil_backup.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
