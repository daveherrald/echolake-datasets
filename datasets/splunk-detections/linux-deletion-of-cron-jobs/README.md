# Linux Deletion Of Cron Jobs

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the deletion of cron jobs on a Linux machine. It leverages filesystem event logs to identify when files within the "/etc/cron.*" directory are deleted. This activity is significant because attackers or malware may delete cron jobs to disable scheduled security tasks or evade detection mechanisms. If confirmed malicious, this action could allow an attacker to disrupt system operations, evade security measures, or facilitate further malicious activities such as data wiping, as seen with the acidrain malware.

## MITRE ATT&CK

- T1070.004
- T1485

## Analytic Stories

- AcidRain
- Data Destruction
- AcidPour

## Data Sources

- Sysmon for Linux EventID 11

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/acidrain/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_deletion_of_cron_jobs.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
