# Windows Privilege Escalation Suspicious Process Elevation

**Type:** TTP

**Author:** Steven Dick

## Description

This dataset contains sample data for detecting when a process running with low or medium integrity from a user account spawns an elevated process with high or system integrity in suspicious locations. This behavior is identified using process execution data from Windows process monitoring or Sysmon EventID 1. This activity is significant as it may indicate a threat actor successfully elevating privileges, which is a common tactic in advanced attacks. If confirmed malicious, this could allow the attacker to execute code with higher privileges, potentially leading to full system compromise and persistent access.

## MITRE ATT&CK

- T1068
- T1548
- T1134

## Analytic Stories

- Windows Privilege Escalation
- BlackSuit Ransomware
- GhostRedirector IIS Module and Rungan Backdoor

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 1

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1068/windows_escalation_behavior/windows_escalation_behavior_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_privilege_escalation_suspicious_process_elevation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
