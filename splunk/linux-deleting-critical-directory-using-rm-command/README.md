# Linux Deleting Critical Directory Using RM Command

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the deletion of critical directories on a Linux machine using the `rm` command with argument rf. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions targeting directories like /boot, /var/log, /etc, and /dev. This activity is significant because deleting these directories can severely disrupt system operations and is often associated with destructive campaigns like Industroyer2. If confirmed malicious, this action could lead to system instability, data loss, and potential downtime, making it crucial for immediate investigation and response.

## MITRE ATT&CK

- T1485

## Analytic Stories

- AwfulShred
- Data Destruction
- Industroyer2

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/rm_shred_critical_dir/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_deleting_critical_directory_using_rm_command.yml)*
