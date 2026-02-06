# Domain Controller Discovery with Wmic

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies the execution of `wmic.exe` with command-line arguments used to discover domain controllers in a Windows domain. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. This activity is significant because it is commonly used by adversaries and Red Teams for situational awareness and Active Directory discovery. If confirmed malicious, this behavior could allow attackers to map out the network, identify key systems, and plan further attacks, potentially leading to unauthorized access and data exfiltration.

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

*Source: [Splunk Security Content](detections/endpoint/domain_controller_discovery_with_wmic.yml)*
