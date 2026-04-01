# Cisco ASA - Device File Copy Activity

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects file copy activity on Cisco ASA devices via CLI or ASDM.
Adversaries may copy device files including configurations, logs, packet captures, or system files for reconnaissance, credential extraction, or data exfiltration. While legitimate file operations occur during backups and maintenance, unauthorized copies may indicate malicious activity.
The detection monitors for command execution events (message ID 111008 or 111010) containing copy commands targeting running-config, startup-config, packet capture files, or other system files from disk0:, flash:, system:, or capture: locations.
Investigate unexpected file copies, especially from non-administrative accounts, during unusual hours, or when combined with other suspicious activities.


## MITRE ATT&CK

- T1005
- T1530

## Analytic Stories

- Suspicious Cisco Adaptive Security Appliance Activity
- ArcaneDoor

## Data Sources

- Cisco ASA Logs

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:asa
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_asa/generic/cisco_asa_generic_logs.log


---

*Source: [Splunk Security Content](detections/application/cisco_asa___device_file_copy_activity.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
