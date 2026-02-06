# Windows Anonymous Pipe Activity

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the creation or connection of anonymous pipes for inter-process communication (IPC) within a Windows environment. Anonymous pipes are commonly used by legitimate system processes, services, and applications to transfer data between related processes. However, adversaries frequently abuse anonymous pipes to facilitate stealthy process injection, command-and-control (C2) communication, credential theft, or privilege escalation. This detection monitors for unusual anonymous pipe activity, particularly involving non-system processes, unsigned executables, or unexpected parent-child process relationships. While legitimate use cases exist—such as Windows services, software installers, or security tools—unusual or high-frequency anonymous pipe activity should be investigated for potential malware, persistence mechanisms, or lateral movement techniques.

## MITRE ATT&CK

- T1559

## Analytic Stories

- Salt Typhoon
- China-Nexus Threat Activity
- SnappyBee
- Interlock Rat
- Castle RAT

## Data Sources

- Sysmon EventID 17
- Sysmon EventID 18

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1559/anonymous_pipe/anonymouspipe.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_anonymous_pipe_activity.yml)*
