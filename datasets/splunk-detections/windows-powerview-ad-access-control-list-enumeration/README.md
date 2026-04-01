# Windows PowerView AD Access Control List Enumeration

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of PowerView PowerShell cmdlets `Get-ObjectAcl` or `Get-DomainObjectAcl`, which are used to enumerate Access Control List (ACL) permissions for Active Directory objects. It leverages Event ID 4104 from PowerShell Script Block Logging to identify this activity. This behavior is significant as it may indicate an attempt to discover weak permissions in Active Directory, potentially leading to privilege escalation. If confirmed malicious, attackers could exploit these permissions to gain unauthorized access or escalate their privileges within the network.

## MITRE ATT&CK

- T1078.002
- T1069

## Analytic Stories

- Active Directory Discovery
- Active Directory Privilege Escalation
- Rhysida Ransomware

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.002/powerview_acl_enumeration/windows-powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powerview_ad_access_control_list_enumeration.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
