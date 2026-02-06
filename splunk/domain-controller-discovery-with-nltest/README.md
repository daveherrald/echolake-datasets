# Domain Controller Discovery with Nltest

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of `nltest.exe` with command-line arguments `/dclist:` or `/dsgetdc:` to discover domain controllers. It leverages Endpoint Detection and Response (EDR) data, focusing on process names and command-line arguments. This activity is significant because both Red Teams and adversaries use `nltest.exe` for situational awareness and Active Directory discovery. If confirmed malicious, this behavior could allow attackers to map out domain controllers, facilitating further attacks such as privilege escalation or lateral movement within the network.

## MITRE ATT&CK

- T1018

## Analytic Stories

- Active Directory Discovery
- CISA AA23-347A
- Medusa Ransomware
- BlackSuit Ransomware
- Rhysida Ransomware
- NetSupport RMM Tool Abuse

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1018/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/domain_controller_discovery_with_nltest.yml)*
