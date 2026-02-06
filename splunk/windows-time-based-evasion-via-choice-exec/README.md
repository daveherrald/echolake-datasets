# Windows Time Based Evasion via Choice Exec

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the use of choice.exe in batch files as a delay tactic, a technique observed in SnakeKeylogger malware. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as it indicates potential time-based evasion techniques used by malware to avoid detection. If confirmed malicious, this behavior could allow attackers to execute code stealthily, delete malicious files, and persist on compromised hosts, making it crucial for SOC analysts to investigate promptly.

## MITRE ATT&CK

- T1497.003

## Analytic Stories

- Snake Keylogger
- 0bj3ctivity Stealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1497.003/time_delay_using_choice_exe/snakekeylogger_choice.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_time_based_evasion_via_choice_exec.yml)*
