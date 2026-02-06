# Linux Impair Defenses Process Kill

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies the execution of the 'pkill' command, which is used to terminate processes on a Linux system. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant because threat actors often use 'pkill' to disable security defenses or terminate critical processes, facilitating further malicious actions. If confirmed malicious, this behavior could lead to the disruption of security applications, enabling attackers to evade detection and potentially corrupt or destroy files on the targeted system.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- AwfulShred
- Data Destruction
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/awfulshred/test1/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_impair_defenses_process_kill.yml)*
