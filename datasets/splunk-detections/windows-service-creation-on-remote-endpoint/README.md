# Windows Service Creation on Remote Endpoint

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying the creation of a Windows Service on a remote endpoint using `sc.exe`. It detects this activity by analyzing process execution logs from Endpoint Detection and Response (EDR) agents, focusing on command-line arguments that include remote paths and service creation commands. This behavior is significant because adversaries often exploit the Service Control Manager for lateral movement and remote code execution. If confirmed malicious, this activity could allow attackers to execute arbitrary code on remote systems, potentially leading to further compromise and persistence within the network.

## MITRE ATT&CK

- T1543.003

## Analytic Stories

- China-Nexus Threat Activity
- CISA AA23-347A
- SnappyBee
- Salt Typhoon
- Active Directory Lateral Movement

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1543.003/lateral_movement/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_service_creation_on_remote_endpoint.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
