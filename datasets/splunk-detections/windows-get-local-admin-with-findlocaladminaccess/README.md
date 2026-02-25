# Windows Get Local Admin with FindLocalAdminAccess

**Type:** TTP

**Author:** Gowthamaraj Rajendran, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of the `Find-LocalAdminAccess` cmdlet using PowerShell Script Block Logging (EventCode=4104). This cmdlet is part of PowerView, a toolkit for Windows domain enumeration. Identifying the use of `Find-LocalAdminAccess` is crucial as adversaries may use it to find machines where the current user has local administrator access, facilitating lateral movement or privilege escalation. If confirmed malicious, this activity could allow attackers to target and compromise additional systems within the network, significantly increasing their control and access to sensitive information.

## MITRE ATT&CK

- T1087.002

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/AD_discovery/windows-powershell-LocalAdminAccess-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_get_local_admin_with_findlocaladminaccess.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
