# Windows WBAdmin File Recovery From Backup

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for identifying the execution of wbadmin.exe with arguments indicative of restoring files from an existing backup. 
WBAdmin is a legitimate Windows Backup utility used for creating, managing, and restoring backups. However, adversaries may abuse it to restore specific files (e.g., sensitive credentials, configuration files, or malware stagers) from prior backups to regain access or re-establish persistence after cleanup or encryption events.
Monitoring this behavior is important because restoring individual files from a system backup outside of approved recovery workflows may indicate an attacker attempting to retrieve deleted or encrypted data, recover previously dropped payloads, or access prior system states as part of post-compromise activity.
If confirmed malicious, this action could enable attackers to regain operational footholds, extract sensitive data, or restore tampered components, undermining remediation and containment efforts.


## MITRE ATT&CK

- T1490
- T1565.001

## Analytic Stories

- Credential Dumping

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1565.001/wbadmin_recovery/wbadmin_recovery.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_wbadmin_file_recovery_from_backup.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
