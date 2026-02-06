# Windows Privilege Escalation System Process Without System Parent

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic detects any system integrity level process spawned by a non-system account. It leverages Sysmon EventID 1, focusing on process integrity and parent user data. This behavior is significant as it often indicates successful privilege escalation to SYSTEM from a user-controlled process or service. If confirmed malicious, this activity could allow an attacker to gain full control over the system, execute arbitrary code, and potentially compromise the entire environment.

## MITRE ATT&CK

- T1068
- T1548
- T1134

## Analytic Stories

- Windows Privilege Escalation
- BlackSuit Ransomware

## Data Sources

- Sysmon EventID 1

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1068/windows_escalation_behavior/windows_escalation_behavior_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_privilege_escalation_system_process_without_system_parent.yml)*
