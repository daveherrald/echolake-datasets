# Windows Security Account Manager Stopped

**Type:** TTP

**Author:** Rod Soto, Jose Hernandez, Splunk

## Description

The following analytic detects the stopping of the Windows Security Account Manager (SAM) service via command-line, typically using the "net stop samss" command. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant because stopping the SAM service can disrupt authentication mechanisms and is often associated with ransomware attacks like Ryuk. If confirmed malicious, this action could lead to unauthorized access, privilege escalation, and potential system-wide compromise.

## MITRE ATT&CK

- T1489

## Analytic Stories

- Compromised Windows Host
- Ryuk Ransomware
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ryuk/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_security_account_manager_stopped.yml)*
