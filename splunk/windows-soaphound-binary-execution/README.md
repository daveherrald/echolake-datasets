# Windows SOAPHound Binary Execution

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of the SOAPHound binary (`soaphound.exe`) with specific command-line arguments. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names, command-line arguments, and other process-related metadata. This activity is significant because SOAPHound is a known tool used for credential dumping and other malicious activities. If confirmed malicious, this behavior could allow an attacker to extract sensitive information, escalate privileges, or persist within the environment, posing a severe threat to organizational security.

## MITRE ATT&CK

- T1069.001
- T1069.002
- T1087.001
- T1087.002
- T1482

## Analytic Stories

- Windows Discovery Techniques
- Compromised Windows Host

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/soaphound/sysmon_soaphound.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_soaphound_binary_execution.yml)*
