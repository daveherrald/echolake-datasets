# Windows ESX Admins Group Creation via Net

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This analytic detects attempts to create an "ESX Admins" group using the Windows net.exe or net1.exe commands. This activity may indicate an attempt to exploit the VMware ESXi Active Directory Integration Authentication Bypass vulnerability (CVE-2024-37085). Attackers can use this method to gain unauthorized access to ESXi hosts by recreating the "ESX Admins" group after its deletion from Active Directory.

## MITRE ATT&CK

- T1136.002
- T1136.001

## Analytic Stories

- VMware ESXi AD Integration Authentication Bypass CVE-2024-37085

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/windows-sysmon-esxadmins.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_esx_admins_group_creation_via_net.yml)*
