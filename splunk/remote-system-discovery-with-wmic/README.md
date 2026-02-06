# Remote System Discovery with Wmic

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of `wmic.exe` with specific command-line arguments used to discover remote systems within a domain. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as it indicates potential reconnaissance efforts by adversaries to map out network resources and Active Directory structures. If confirmed malicious, this behavior could allow attackers to gain situational awareness, identify critical systems, and plan further attacks, potentially leading to unauthorized access and data exfiltration.

## MITRE ATT&CK

- T1018

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1018/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/remote_system_discovery_with_wmic.yml)*
