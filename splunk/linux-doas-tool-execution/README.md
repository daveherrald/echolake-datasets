# Linux Doas Tool Execution

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of the 'doas' tool on a Linux host. This tool allows standard users to perform tasks with root privileges, similar to 'sudo'. The detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as 'doas' can be exploited by adversaries to gain elevated privileges on a compromised host. If confirmed malicious, this could lead to unauthorized administrative access, potentially compromising the entire system.

## MITRE ATT&CK

- T1548.003

## Analytic Stories

- Linux Privilege Escalation
- Linux Persistence Techniques

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.003/doas_exec/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_doas_tool_execution.yml)*
