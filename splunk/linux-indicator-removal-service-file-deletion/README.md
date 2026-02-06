# Linux Indicator Removal Service File Deletion

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the deletion of Linux service unit configuration files by suspicious processes. It leverages Endpoint Detection and Response (EDR) telemetry, focusing on processes executing the 'rm' command targeting '.service' files. This activity is significant as it may indicate malware attempting to disable critical services or security products, a common defense evasion tactic. If confirmed malicious, this behavior could lead to service disruption, security tool incapacitation, or complete system compromise, severely impacting the integrity and availability of the affected Linux host.

## MITRE ATT&CK

- T1070.004

## Analytic Stories

- AwfulShred
- Data Destruction

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/awfulshred/test1/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_indicator_removal_service_file_deletion.yml)*
