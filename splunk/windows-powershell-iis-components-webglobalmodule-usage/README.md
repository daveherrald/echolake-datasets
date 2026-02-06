# Windows PowerShell IIS Components WebGlobalModule Usage

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the usage of PowerShell Cmdlets - New-WebGlobalModule, Enable-WebGlobalModule, and Set-WebGlobalModule, which are used to create, enable, or modify IIS Modules. This detection leverages PowerShell Script Block Logging, specifically monitoring EventCode 4104 for these cmdlets. This activity is significant as adversaries may use these lesser-known cmdlets to manipulate IIS configurations, similar to AppCmd.exe, potentially bypassing traditional defenses. If confirmed malicious, this could allow attackers to persist in the environment, manipulate web server behavior, or escalate privileges.

## MITRE ATT&CK

- T1505.004

## Analytic Stories

- GhostRedirector IIS Module and Rungan Backdoor
- IIS Components

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.004/4104_windows-powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powershell_iis_components_webglobalmodule_usage.yml)*
