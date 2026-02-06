# Linux Auditd Change File Owner To Root

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the use of the 'chown' command to change a file owner to 'root' on a Linux system. It leverages Linux Auditd telemetry, specifically monitoring command-line executions and process details. This activity is significant as it may indicate an attempt to escalate privileges by adversaries, malware, or red teamers. If confirmed malicious, this action could allow an attacker to gain root-level access, leading to full control over the compromised host and potential persistence within the environment.

## MITRE ATT&CK

- T1222.002

## Analytic Stories

- Linux Living Off The Land
- Linux Privilege Escalation
- Linux Persistence Techniques
- Compromised Linux Host

## Data Sources

- Linux Auditd Proctitle

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.002/linux_auditd_chown_root/auditd_proctitle_chown_root.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_change_file_owner_to_root.yml)*
