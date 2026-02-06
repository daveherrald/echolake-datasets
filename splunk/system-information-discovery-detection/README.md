# System Information Discovery Detection

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic identifies system information discovery techniques, such as the execution of commands like `wmic qfe`, `systeminfo`, and `hostname`. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs. This activity is significant because attackers often use these commands to gather system configuration details, which can aid in further exploitation. If confirmed malicious, this behavior could allow attackers to tailor their attacks based on the discovered system information, potentially leading to privilege escalation, persistence, or data exfiltration.

## MITRE ATT&CK

- T1082

## Analytic Stories

- Windows Discovery Techniques
- Gozi Malware
- Medusa Ransomware
- BlackSuit Ransomware
- Cleo File Transfer Software
- Interlock Ransomware
- LAMEHUG
- NetSupport RMM Tool Abuse

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1082/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/system_information_discovery_detection.yml)*
