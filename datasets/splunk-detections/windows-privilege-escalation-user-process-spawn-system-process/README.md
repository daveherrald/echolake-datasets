# Windows Privilege Escalation User Process Spawn System Process

**Type:** TTP

**Author:** Steven Dick

## Description

This dataset contains sample data for detecting when a process with low, medium, or high integrity spawns a system integrity process from a user-controlled location. This behavior is indicative of privilege escalation attempts where attackers elevate their privileges to SYSTEM level from a user-controlled process or service. The detection leverages Sysmon data, specifically Event ID 15, to identify such transitions. Monitoring this activity is crucial as it can signify an attacker gaining SYSTEM-level access, potentially leading to full control over the affected system, unauthorized access to sensitive data, and further malicious activities.

## MITRE ATT&CK

- T1068
- T1548
- T1134

## Analytic Stories

- Windows Privilege Escalation
- Compromised Windows Host
- BlackSuit Ransomware
- GhostRedirector IIS Module and Rungan Backdoor

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 1

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1068/windows_escalation_behavior/windows_escalation_behavior_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_privilege_escalation_user_process_spawn_system_process.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
