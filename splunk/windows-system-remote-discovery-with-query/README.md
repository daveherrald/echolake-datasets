# Windows System Remote Discovery With Query

**Type:** Anomaly

**Author:** Steven Dick

## Description

The following analytic detects the execution of `query.exe` with command-line arguments aimed at discovering data on remote devices. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as adversaries may use `query.exe` to gain situational awareness and perform Active Directory discovery on compromised endpoints. If confirmed malicious, this behavior could allow attackers to identify various details about a system, aiding in further lateral movement and privilege escalation within the network.

## MITRE ATT&CK

- T1033

## Analytic Stories

- Active Directory Discovery
- Medusa Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1033/query_remote_usage/query_remote_usage.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_system_remote_discovery_with_query.yml)*
