# Wmic Group Discovery

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies the use of `wmic.exe` to enumerate local groups on an endpoint. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs, including command-line details. Monitoring this activity is significant as it can indicate reconnaissance efforts by an attacker to understand group memberships, which could be a precursor to privilege escalation or lateral movement. If confirmed malicious, this activity could allow an attacker to map out privileged groups, aiding in further exploitation and persistence within the environment.

## MITRE ATT&CK

- T1069.001

## Analytic Stories

- Active Directory Discovery
- LAMEHUG

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.001/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/wmic_group_discovery.yml)*
