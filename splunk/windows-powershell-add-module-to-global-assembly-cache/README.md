# Windows PowerShell Add Module to Global Assembly Cache

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the addition of a DLL to the Windows Global Assembly Cache (GAC) using PowerShell. It leverages PowerShell Script Block Logging to identify commands containing "system.enterpriseservices.internal.publish". This activity is significant because adding a DLL to the GAC allows it to be shared across multiple applications, potentially enabling an adversary to execute malicious code system-wide. If confirmed malicious, this could lead to widespread code execution, privilege escalation, and persistent access across the operating system, posing a severe security risk.

## MITRE ATT&CK

- T1505.004

## Analytic Stories

- IIS Components

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.004/pwsh_publish_powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powershell_add_module_to_global_assembly_cache.yml)*
