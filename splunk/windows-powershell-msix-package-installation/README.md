# Windows PowerShell MSIX Package Installation

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of PowerShell commands to install unsigned AppX packages using Add-AppxPackage or Add-AppPackage cmdlets with the -AllowUnsigned flag. This detection leverages PowerShell Script Block Logging (EventCode=4104) to capture the full command content. This activity is significant as adversaries may use unsigned AppX packages to install malicious applications, bypass security controls, or establish persistence. If confirmed malicious, this could allow attackers to install unauthorized applications that may contain malware, backdoors, or other malicious components.

## MITRE ATT&CK

- T1059.001
- T1547.001

## Analytic Stories

- Malicious PowerShell
- MSIX Package Abuse

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1553.005/msix_unsigned/windows-powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powershell_msix_package_installation.yml)*
