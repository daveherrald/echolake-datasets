# Network Connection Discovery With Arp

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of `arp.exe` with the `-a` flag, which is used to list network connections on a compromised system. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names, command-line executions, and related telemetry. Monitoring this activity is significant because both Red Teams and adversaries use `arp.exe` for situational awareness and Active Directory discovery. If confirmed malicious, this activity could allow attackers to map the network, identify active devices, and plan further lateral movement or attacks.

## MITRE ATT&CK

- T1049

## Analytic Stories

- Active Directory Discovery
- Qakbot
- Windows Post-Exploitation
- Prestige Ransomware
- Volt Typhoon
- IcedID
- Interlock Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1049/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/network_connection_discovery_with_arp.yml)*
