# Windows PowerShell Process With Malicious String

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic detects the execution of multiple offensive toolkits and commands through the process execution datamodel. This method captures commands given directly to powershell.exe, allowing for the identification of suspicious activities including several well-known tools used for credential theft, lateral movement, and persistence. If confirmed malicious, this could lead to unauthorized access, privilege escalation, and potential compromise of sensitive information within the environment.

## MITRE ATT&CK

- T1059.001

## Analytic Stories

- Malicious PowerShell

## Data Sources

- Windows Event Log Security 4688
- Sysmon EventID 1
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powershell_process_with_malicious_string.yml)*
