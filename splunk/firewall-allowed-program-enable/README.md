# Firewall Allowed Program Enable

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the modification of a firewall rule to allow the execution of a specific application. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events with command-line arguments related to firewall rule changes. This activity is significant as it may indicate an attempt to bypass firewall restrictions, potentially allowing unauthorized applications to communicate over the network. If confirmed malicious, this could enable an attacker to execute arbitrary code, escalate privileges, or maintain persistence within the target environment.

## MITRE ATT&CK

- T1562.004

## Analytic Stories

- BlackByte Ransomware
- NjRAT
- PlugX
- Windows Defense Evasion Tactics
- Medusa Ransomware
- Azorult

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/vilsel/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/firewall_allowed_program_enable.yml)*
