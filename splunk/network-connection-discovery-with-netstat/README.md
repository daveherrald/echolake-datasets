# Network Connection Discovery With Netstat

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of `netstat.exe` with command-line arguments to list network connections on a system. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names, command-line executions, and parent processes. This activity is significant as both Red Teams and adversaries use `netstat.exe` for situational awareness and Active Directory discovery. If confirmed malicious, this behavior could allow attackers to map network connections, identify critical systems, and plan further lateral movement or data exfiltration.

## MITRE ATT&CK

- T1049

## Analytic Stories

- CISA AA22-277A
- Windows Post-Exploitation
- Active Directory Discovery
- CISA AA23-347A
- Prestige Ransomware
- Qakbot
- PlugX
- Medusa Ransomware
- Volt Typhoon

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1049/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/network_connection_discovery_with_netstat.yml)*
