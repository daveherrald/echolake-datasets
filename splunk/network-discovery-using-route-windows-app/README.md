# Network Discovery Using Route Windows App

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of the `route.exe` Windows application, commonly used for network discovery. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events. This activity is significant because adversaries often use `route.exe` to map network routes and identify potential targets within a network. If confirmed malicious, this behavior could allow attackers to gain insights into network topology, facilitating lateral movement and further exploitation. Note that false positives may occur due to legitimate administrative tasks or automated scripts.

## MITRE ATT&CK

- T1016.001

## Analytic Stories

- Active Directory Discovery
- Qakbot
- CISA AA22-277A
- Windows Post-Exploitation
- Prestige Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/vilsel/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/network_discovery_using_route_windows_app.yml)*
