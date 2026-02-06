# PowerShell Get LocalGroup Discovery

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies the use of the `get-localgroup` command executed via PowerShell or cmd.exe to enumerate local groups on an endpoint. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. Monitoring this activity is significant as it may indicate an attacker attempting to gather information about local group memberships, which can be a precursor to privilege escalation. If confirmed malicious, this activity could allow an attacker to identify and target privileged accounts, potentially leading to unauthorized access and control over the system.

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

*Source: [Splunk Security Content](detections/endpoint/powershell_get_localgroup_discovery.yml)*
