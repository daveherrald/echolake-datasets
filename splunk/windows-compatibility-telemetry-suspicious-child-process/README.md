# Windows Compatibility Telemetry Suspicious Child Process

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic detects the execution of CompatTelRunner.exe with parameters indicative of a process not part of the normal "Microsoft Compatibility Appraiser" telemetry collection. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names, parent processes, and command-line arguments. This activity is significant because CompatTelRunner.exe and the "Microsoft Compatibility Appraiser" task always run as System and can be used to elevate privileges or establish a highly privileged persistence mechanism. If confirmed malicious, this could enable unauthorized code execution, privilege escalation, or persistent access to the compromised system.

## MITRE ATT&CK

- T1546
- T1053.005

## Analytic Stories

- Windows Persistence Techniques

## Data Sources

- Windows Event Log Security 4688
- Sysmon EventID 1
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546/compattelrunner_abuse/compattelrunner_abuse.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_compatibility_telemetry_suspicious_child_process.yml)*
