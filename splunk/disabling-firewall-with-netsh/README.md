# Disabling Firewall with Netsh

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies the disabling of the firewall using the netsh application. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions that include keywords like "firewall," "off," or "disable." This activity is significant because disabling the firewall can expose the system to external threats, allowing malware to communicate with its command and control (C2) server. If confirmed malicious, this action could lead to unauthorized data exfiltration, further malware downloads, and broader network compromise.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Windows Defense Evasion Tactics
- BlackByte Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/win_app_defender_disabling/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/disabling_firewall_with_netsh.yml)*
