# Linux Change File Owner To Root

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the use of the 'chown' command to change a file owner to 'root' on a Linux system. It leverages Endpoint Detection and Response (EDR) telemetry, specifically monitoring command-line executions and process details. This activity is significant as it may indicate an attempt to escalate privileges by adversaries, malware, or red teamers. If confirmed malicious, this action could allow an attacker to gain root-level access, leading to full control over the compromised host and potential persistence within the environment.

## MITRE ATT&CK

- T1222.002

## Analytic Stories

- Linux Privilege Escalation
- Linux Persistence Techniques
- Linux Living Off The Land

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.001/chmod_uid/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_change_file_owner_to_root.yml)*
