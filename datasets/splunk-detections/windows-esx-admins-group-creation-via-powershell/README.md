# Windows ESX Admins Group Creation via PowerShell

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This analytic detects attempts to create an "ESX Admins" group using PowerShell commands. This activity may indicate an attempt to exploit the VMware ESXi Active Directory Integration Authentication Bypass vulnerability (CVE-2024-37085). Attackers can use this method to gain unauthorized access to ESXi hosts by recreating the 'ESX Admins' group after its deletion from Active Directory.

## MITRE ATT&CK

- T1136.002
- T1136.001

## Analytic Stories

- VMware ESXi AD Integration Authentication Bypass CVE-2024-37085

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/windows-powershell-esxadmins.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_esx_admins_group_creation_via_powershell.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
