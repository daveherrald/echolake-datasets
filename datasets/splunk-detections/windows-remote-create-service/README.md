# Windows Remote Create Service

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying the creation of a new service on a remote endpoint using sc.exe. It leverages data from Endpoint Detection and Response (EDR) agents, specifically monitoring for EventCode 7045, which indicates a new service creation. This activity is significant as it may indicate lateral movement or remote code execution attempts by an attacker. If confirmed malicious, this could allow the attacker to establish persistence, escalate privileges, or execute arbitrary code on the remote system, potentially leading to further compromise of the network.

## MITRE ATT&CK

- T1543.003

## Analytic Stories

- Active Directory Lateral Movement
- CISA AA23-347A
- BlackSuit Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1543.003/atomic_red_team/remote_service_create_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_remote_create_service.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
