# Linux Auditd At Application Execution

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of the "At" application in Linux, which can be used by attackers to create persistence entries on a compromised host. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and parent process names associated with "at" or "atd". This activity is significant because the "At" application can be exploited to maintain unauthorized access or deliver additional malicious payloads. If confirmed malicious, this behavior could lead to data theft, ransomware attacks, or other severe consequences. Immediate investigation is required to determine the legitimacy of the execution and mitigate potential risks.

## MITRE ATT&CK

- T1053.002

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.002/linux_new_auditd_at/linux_auditd_new_at.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_at_application_execution.yml)*
