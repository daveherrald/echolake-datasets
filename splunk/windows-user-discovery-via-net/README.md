# Windows User Discovery Via Net

**Type:** Hunting

**Author:** Mauricio Velazco, Teoderick Contreras, Nasreddine Bencherchali, Splunk

## Description

The following analytic detects the execution of `net.exe` or `net1.exe` with command-line arguments `user` or `users` to query local user accounts. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as it indicates potential reconnaissance efforts by adversaries to enumerate local users, which is a common step in situational awareness and Active Directory discovery. If confirmed malicious, this behavior could lead to further attacks, including privilege escalation and lateral movement within the network.

## MITRE ATT&CK

- T1087.001

## Analytic Stories

- Active Directory Discovery
- Sandworm Tools
- Medusa Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.001/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_user_discovery_via_net.yml)*
