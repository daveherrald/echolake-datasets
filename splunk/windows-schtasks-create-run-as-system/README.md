# Windows Schtasks Create Run As System

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the creation of a new scheduled task using Schtasks.exe to run as the SYSTEM user. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions and process details. This activity is significant as it often indicates an attempt to gain elevated privileges or maintain persistence within the environment. If confirmed malicious, an attacker could execute code with SYSTEM-level privileges, potentially leading to data theft, ransomware deployment, or further system compromise. Immediate investigation and mitigation are crucial to prevent further damage.

## MITRE ATT&CK

- T1053.005

## Analytic Stories

- Medusa Ransomware
- Windows Persistence Techniques
- Qakbot
- Scheduled Tasks
- Castle RAT

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/schtask_system/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_schtasks_create_run_as_system.yml)*
