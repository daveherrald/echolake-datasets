# Windows Modify Registry MaxConnectionPerServer

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying a suspicious modification of the Windows registry setting for max connections per server. It detects changes to specific registry paths using data from the Endpoint.Registry datamodel. This activity is significant because altering this setting can be exploited by attackers to increase the number of concurrent connections to a remote server, potentially facilitating DDoS attacks or enabling more effective lateral movement within a compromised network. If confirmed malicious, this could lead to network disruption or further compromise of additional systems.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Warzone RAT

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/warzone_rat/maxconnectionperserver/registry_event.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_maxconnectionperserver.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
