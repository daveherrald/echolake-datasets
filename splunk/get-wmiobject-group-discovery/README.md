# Get WMIObject Group Discovery

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the use of the `Get-WMIObject Win32_Group` command executed via PowerShell to enumerate local groups on an endpoint. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. Identifying local groups can be a precursor to privilege escalation or lateral movement. If confirmed malicious, this activity could allow an attacker to map out group memberships, aiding in further exploitation or unauthorized access to sensitive resources.

## MITRE ATT&CK

- T1069.001

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.001/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/get_wmiobject_group_discovery.yml)*
