# Shim Database Installation With Suspicious Parameters

**Type:** TTP

**Author:** David Dorsey, Splunk

## Description

The following analytic detects the execution of sdbinst.exe with parameters indicative of silently creating a shim database. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names, parent processes, and command-line arguments. This activity is significant because shim databases can be used to intercept and manipulate API calls, potentially allowing attackers to bypass security controls or achieve persistence. If confirmed malicious, this could enable unauthorized code execution, privilege escalation, or persistent access to the compromised system.

## MITRE ATT&CK

- T1546.011

## Analytic Stories

- Windows Persistence Techniques
- Compromised Windows Host

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.011/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/shim_database_installation_with_suspicious_parameters.yml)*
