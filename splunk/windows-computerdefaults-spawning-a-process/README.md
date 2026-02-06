# Windows ComputerDefaults Spawning a Process

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the spawning of ComputerDefaults.exe, a Windows system process used to manage default application associations. While normally legitimate, this process can be exploited by attackers to bypass User Account Control (UAC) and execute unauthorized code with elevated privileges. Detection focuses on abnormal execution patterns, unusual parent-child process relationships, or deviations from standard paths. Such behavior may indicate attempts to modify system defaults or run malicious scripts undetected. Monitoring ComputerDefaults.exe is critical to identify potential security threats, prevent privilege escalation, and maintain system integrity by distinguishing normal operations from suspicious activity.

## MITRE ATT&CK

- T1548.002

## Analytic Stories

- Castle RAT

## Data Sources

- Sysmon EventID 1

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.002/computerdefaults_spawn_proc/computerdefaults_process.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_computerdefaults_spawning_a_process.yml)*
