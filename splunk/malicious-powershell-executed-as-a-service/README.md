# Malicious Powershell Executed As A Service

**Type:** TTP

**Author:** Ryan Becwar

## Description

The following analytic identifies the execution of malicious PowerShell commands or payloads via the Windows SC.exe utility. It detects this activity by analyzing Windows System logs (EventCode 7045) and filtering for specific PowerShell-related patterns in the ImagePath field. This behavior is significant because it indicates potential abuse of the Windows Service Control Manager to run unauthorized or harmful scripts, which could lead to system compromise. If confirmed malicious, this activity could allow attackers to execute arbitrary code, escalate privileges, or maintain persistence within the environment.

## MITRE ATT&CK

- T1569.002

## Analytic Stories

- Compromised Windows Host
- Rhysida Ransomware
- Malicious PowerShell

## Data Sources

- Windows Event Log System 7045

## Sample Data

- **Source:** XmlWinEventLog:System
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1569.002/malicious_powershell_executed_as_a_service/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/malicious_powershell_executed_as_a_service.yml)*
