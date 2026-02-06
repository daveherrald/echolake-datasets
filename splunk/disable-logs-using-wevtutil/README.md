# Disable Logs Using WevtUtil

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of "wevtutil.exe" with parameters to disable event logs. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. This activity is significant because disabling event logs is a common tactic used by ransomware to evade detection and hinder forensic investigations. If confirmed malicious, this action could allow attackers to operate undetected, making it difficult to trace their activities and respond effectively to the incident.

## MITRE ATT&CK

- T1070.001

## Analytic Stories

- Ransomware
- CISA AA23-347A
- Rhysida Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data1/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/disable_logs_using_wevtutil.yml)*
