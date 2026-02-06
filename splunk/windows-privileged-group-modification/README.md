# Windows Privileged Group Modification

**Type:** TTP

**Author:** Brandon Sternfield, Optiv + ClearShark

## Description

This analytic detects modifications to privileged groups in Active Directory, including creation, deletion, and changes to various types of groups such as local, global, universal, and LDAP query groups. It specifically monitors for changes to high-privilege groups like "Administrators", "Domain Admins", "Enterprise Admins", and "ESX Admins", among others. This detection is particularly relevant in the context of potential exploitation of vulnerabilities like the VMware ESXi Active Directory Integration Authentication Bypass (CVE-2024-37085), where attackers may attempt to manipulate privileged groups to gain unauthorized access to systems.

## MITRE ATT&CK

- T1136.001
- T1136.002

## Analytic Stories

- VMware ESXi AD Integration Authentication Bypass CVE-2024-37085
- Scattered Lapsus$ Hunters

## Data Sources

- Windows Event Log Security 4727
- Windows Event Log Security 4731
- Windows Event Log Security 4744
- Windows Event Log Security 4749
- Windows Event Log Security 4754
- Windows Event Log Security 4759
- Windows Event Log Security 4783
- Windows Event Log Security 4790

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/windows-security-esxadmins.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_privileged_group_modification.yml)*
