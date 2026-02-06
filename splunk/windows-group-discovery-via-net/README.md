# Windows Group Discovery Via Net

**Type:** Hunting

**Author:** Michael Haag, Mauricio Velazco, Splunk

## Description

The following analytic identifies the execution of `net.exe` with command-line arguments used to query global, local and domain groups. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. This activity is significant as it indicates potential reconnaissance efforts by adversaries to enumerate local or domain groups, which is a common step in Active Directory or privileged accounts discovery. If confirmed malicious, this behavior could allow attackers to gain insights into the domain structure, aiding in further attacks such as privilege escalation or lateral movement.

## MITRE ATT&CK

- T1069.001
- T1069.002

## Analytic Stories

- Windows Discovery Techniques
- Windows Post-Exploitation
- Graceful Wipe Out Attack
- Active Directory Discovery
- Prestige Ransomware
- Medusa Ransomware
- Azorult
- Cleo File Transfer Software
- Rhysida Ransomware
- IcedID
- Volt Typhoon
- Microsoft WSUS CVE-2025-59287

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.002/AD_discovery/windows-sysmon.log

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.001/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_group_discovery_via_net.yml)*
