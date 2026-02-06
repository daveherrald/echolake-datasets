# Linux Auditd Doas Tool Execution

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of the 'doas' tool on a Linux host. This tool allows standard users to perform tasks with root privileges, similar to 'sudo'. The detection leverages data from Linux Auditd, focusing on process names and command-line executions. This activity is significant as 'doas' can be exploited by adversaries to gain elevated privileges on a compromised host. If confirmed malicious, this could lead to unauthorized administrative access, potentially compromising the entire system.

## MITRE ATT&CK

- T1548.003

## Analytic Stories

- Linux Privilege Escalation
- Linux Persistence Techniques
- Compromised Linux Host

## Data Sources

- Linux Auditd Syscall

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.003/linux_auditd_doas_new/linux_auditd_new_doas.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_doas_tool_execution.yml)*
