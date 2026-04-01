# Windows Service Creation Using Registry Entry

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

This dataset contains sample data for detecting the modification of registry keys that define Windows services using reg.exe. This detection leverages Splunk to search for specific keywords in the registry path, value name, and value data fields. This activity is significant because it indicates potential unauthorized changes to service configurations, a common persistence technique used by attackers. If confirmed malicious, this could allow an attacker to maintain access, escalate privileges, or move laterally within the network, leading to data theft, ransomware, or other damaging outcomes.

## MITRE ATT&CK

- T1574.011

## Analytic Stories

- PlugX
- CISA AA23-347A
- China-Nexus Threat Activity
- Windows Persistence Techniques
- SnappyBee
- Derusbi
- Windows Registry Abuse
- Salt Typhoon
- Active Directory Lateral Movement
- Suspicious Windows Registry Activities
- Crypto Stealer
- Brute Ratel C4

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1574.011/change_registry_path_service/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_service_creation_using_registry_entry.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
