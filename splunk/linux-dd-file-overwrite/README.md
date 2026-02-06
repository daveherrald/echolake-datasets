# Linux DD File Overwrite

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the use of the 'dd' command to overwrite files on a Linux system. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs that include command-line details. This activity is significant because adversaries often use the 'dd' command to destroy or irreversibly overwrite files, disrupting system availability and services. If confirmed malicious, this behavior could lead to data destruction, making recovery difficult and potentially causing significant operational disruptions.

## MITRE ATT&CK

- T1485

## Analytic Stories

- Data Destruction
- Industroyer2

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/linux_dd_file_overwrite/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_dd_file_overwrite.yml)*
