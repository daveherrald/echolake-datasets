# Windows Service Create with Tscon

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects potential RDP Hijacking attempts by identifying the creation of a Windows service using sc.exe with a binary path that includes tscon.exe. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events and command-line arguments. This activity is significant as it indicates an attacker may be trying to hijack a disconnected RDP session, posing a risk of unauthorized access. If confirmed malicious, the attacker could gain control over an existing user session, leading to potential data theft or further system compromise.

## MITRE ATT&CK

- T1543.003
- T1563.002

## Analytic Stories

- Active Directory Lateral Movement
- Compromised Windows Host
- Windows RDP Artifacts and Defense Evasion

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1563.002/rdphijack/tscon_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_service_create_with_tscon.yml)*
