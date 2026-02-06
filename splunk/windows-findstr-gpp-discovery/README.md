# Windows Findstr GPP Discovery

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the use of the findstr command to search for unsecured credentials in Group Policy Preferences (GPP). It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions involving findstr.exe with references to SYSVOL and cpassword. This activity is significant because it indicates an attempt to locate and potentially decrypt embedded credentials in GPP, which could lead to unauthorized access. If confirmed malicious, this could allow an attacker to escalate privileges or gain access to sensitive systems and data within the domain.

## MITRE ATT&CK

- T1552.006

## Analytic Stories

- Active Directory Privilege Escalation

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552.006/findstr_gpp_discovery/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_findstr_gpp_discovery.yml)*
