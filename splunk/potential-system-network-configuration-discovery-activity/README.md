# Potential System Network Configuration Discovery Activity

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

The following analytic identifies the rapid execution of processes used for system network configuration discovery on an endpoint. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process GUIDs, names, parent processes, and command-line executions. This activity can be significant as it may indicate an attacker attempting to map the network, which is a common precursor to lateral movement or further exploitation. If confirmed malicious, this behavior could allow an attacker to gain insights into the network topology, identify critical systems, and plan subsequent attacks, potentially leading to data exfiltration or system compromise.

## MITRE ATT&CK

- T1016

## Analytic Stories

- Unusual Processes

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1016/discovery_commands/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/potential_system_network_configuration_discovery_activity.yml)*
