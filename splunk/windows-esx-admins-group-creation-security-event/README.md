# Windows ESX Admins Group Creation Security Event

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This analytic detects creation, deletion, or modification of the "ESX Admins" group in Active Directory. These events may indicate attempts to exploit the VMware ESXi Active Directory Integration Authentication Bypass vulnerability (CVE-2024-37085).

## MITRE ATT&CK

- T1136.001
- T1136.002

## Analytic Stories

- VMware ESXi AD Integration Authentication Bypass CVE-2024-37085

## Data Sources

- Windows Event Log Security 4727
- Windows Event Log Security 4730
- Windows Event Log Security 4737

## Sample Data

- **Source:** Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/windows-security-esxadmins.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_esx_admins_group_creation_security_event.yml)*
