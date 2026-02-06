# PowerShell Start or Stop Service

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies the use of PowerShell's Start-Service or Stop-Service cmdlets on an endpoint. It leverages PowerShell Script Block Logging to detect these commands. This activity is significant because attackers can manipulate services to disable or stop critical functions, causing system instability or disrupting business operations. If confirmed malicious, this behavior could allow attackers to disable security services, evade detection, or disrupt essential services, leading to potential system downtime and compromised security.

## MITRE ATT&CK

- T1059.001

## Analytic Stories

- Scattered Lapsus$ Hunters
- Active Directory Lateral Movement

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/atomic_red_team/start_stop_service_windows-powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_start_or_stop_service.yml)*
