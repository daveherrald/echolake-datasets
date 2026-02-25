# Windows Steal Authentication Certificates CS Backup

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying the backup of the Active Directory Certificate Services (AD CS) store, detected via Event ID 4876. This event is logged when a backup is performed using the CertSrv.msc UI or the CertUtil.exe -BackupDB command. Monitoring this activity is crucial as unauthorized backups can indicate an attempt to steal authentication certificates, which are critical for secure communications. If confirmed malicious, this activity could allow an attacker to impersonate users, escalate privileges, or access sensitive information, severely compromising the security of the environment.

## MITRE ATT&CK

- T1649

## Analytic Stories

- Windows Certificate Services

## Data Sources

- Windows Event Log Security 4876

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1649/atomic_red_team/4876_windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_steal_authentication_certificates_cs_backup.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
