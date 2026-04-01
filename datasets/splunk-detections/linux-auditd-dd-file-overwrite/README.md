# Linux Auditd Dd File Overwrite

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the use of the 'dd' command to overwrite files on a Linux system. It leverages data from Linux Auditd telemetry, focusing on process execution logs that include command-line details. This activity is significant because adversaries often use the 'dd' command to destroy or irreversibly overwrite files, disrupting system availability and services. If confirmed malicious, this behavior could lead to data destruction, making recovery difficult and potentially causing significant operational disruptions.

## MITRE ATT&CK

- T1485

## Analytic Stories

- Industroyer2
- Data Destruction
- Compromised Linux Host

## Data Sources

- Linux Auditd Proctitle

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/linux_auditd_dd_overwrite/auditd_proctitle_dd_overwrite.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_dd_file_overwrite.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
