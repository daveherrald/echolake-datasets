# Excessive number of service control start as disabled

**Type:** Anomaly

**Author:** Michael Hart, Splunk

## Description

The following analytic detects an excessive number of `sc.exe` processes launched with the command line argument `start= disabled` within a short period. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names, command-line executions, and process GUIDs. This activity is significant as it may indicate an attempt to disable critical services, potentially impairing system defenses. If confirmed malicious, this behavior could allow an attacker to disrupt security mechanisms, hinder incident response, and maintain control over the compromised system.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Windows Defense Evasion Tactics

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/sc_service_start_disabled/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/excessive_number_of_service_control_start_as_disabled.yml)*
