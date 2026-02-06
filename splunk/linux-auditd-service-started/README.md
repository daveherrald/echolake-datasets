# Linux Auditd Service Started

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the suspicious service started. This behavior is critical for a SOC to monitor because it may indicate attempts to gain unauthorized access or maintain control over a system. Such actions could be signs of malicious activity. If confirmed, this could lead to serious consequences, including a compromised system, unauthorized access to sensitive data, or even a wider breach affecting the entire network. Detecting and responding to these signs early is essential to prevent potential security incidents.

## MITRE ATT&CK

- T1569.002

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1569.002/linux_service_start/auditd_proctitle_service_start.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_service_started.yml)*
