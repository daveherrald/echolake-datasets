# Linux Edit Cron Table Parameter

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the suspicious editing of cron jobs in Linux using the crontab command-line parameter (-e). It identifies this activity by monitoring command-line executions involving 'crontab' and the edit parameter. This behavior is significant for a SOC as cron job manipulations can indicate unauthorized persistence attempts or scheduled malicious actions. If confirmed malicious, this activity could lead to system compromise, unauthorized access, or broader network compromise.

## MITRE ATT&CK

- T1053.003

## Analytic Stories

- Linux Privilege Escalation
- Linux Persistence Techniques
- Linux Living Off The Land
- Scheduled Tasks

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.003/crontab_edit_parameter/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_edit_cron_table_parameter.yml)*
