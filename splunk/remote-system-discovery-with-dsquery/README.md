# Remote System Discovery with Dsquery

**Type:** Anomaly

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of `dsquery.exe` with the `computer` argument, which is used to discover remote systems within a domain. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. Remote system discovery is significant as it indicates potential reconnaissance activities by adversaries or Red Teams to map out network resources and Active Directory structures. If confirmed malicious, this activity could lead to further exploitation, lateral movement, and unauthorized access to critical systems within the network.

## MITRE ATT&CK

- T1018

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1018/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/remote_system_discovery_with_dsquery.yml)*
