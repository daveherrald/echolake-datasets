# Linux Auditd Edit Cron Table Parameter

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the suspicious editing of cron jobs in Linux using the crontab command-line parameter (-e). It identifies this activity by monitoring command-line executions involving 'crontab' and the edit parameter. This behavior is significant for a SOC as cron job manipulations can indicate unauthorized persistence attempts or scheduled malicious actions. If confirmed malicious, this activity could lead to system compromise, unauthorized access, or broader network compromise.

## MITRE ATT&CK

- T1053.003

## Analytic Stories

- Scheduled Tasks
- Linux Privilege Escalation
- Linux Persistence Techniques
- Linux Living Off The Land
- Compromised Linux Host

## Data Sources

- Linux Auditd Syscall

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.003/linux_auditd_crontab_edit_new/linux_auditd_new_crontab.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_edit_cron_table_parameter.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
