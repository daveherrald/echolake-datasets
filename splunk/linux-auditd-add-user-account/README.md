# Linux Auditd Add User Account

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the creation of new user accounts on Linux systems using commands like "useradd" or "adduser." It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as adversaries often create new user accounts to establish persistence on compromised hosts. If confirmed malicious, this could allow attackers to maintain access, escalate privileges, and further compromise the system, posing a severe security risk.

## MITRE ATT&CK

- T1136.001

## Analytic Stories

- Linux Privilege Escalation
- Linux Persistence Techniques
- Compromised Linux Host

## Data Sources

- Linux Auditd Proctitle

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/linux_auditd_add_user/auditd_proctitle_user_add.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_add_user_account.yml)*
