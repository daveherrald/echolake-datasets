# Windows File Share Discovery With Powerview

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of the Invoke-ShareFinder PowerShell cmdlet from PowerView. This detection leverages PowerShell Script Block Logging to identify instances where this specific command is executed. Monitoring this activity is crucial as it indicates an attempt to enumerate network file shares, which may contain sensitive information such as backups, scripts, and credentials. If confirmed malicious, this activity could enable an attacker to escalate privileges or move laterally within the network, potentially compromising additional systems and sensitive data.

## MITRE ATT&CK

- T1135

## Analytic Stories

- Active Directory Privilege Escalation
- Active Directory Discovery

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1135/powerview_sharefinder/windows-powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_file_share_discovery_with_powerview.yml)*
