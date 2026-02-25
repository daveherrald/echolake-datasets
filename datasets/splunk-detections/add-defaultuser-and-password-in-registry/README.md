# Add DefaultUser And Password In Registry

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

This dataset contains sample data for detecting suspicious registry modifications that implement auto admin logon by adding DefaultUserName and DefaultPassword values. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" registry path. This activity is significant because it is associated with BlackMatter ransomware, which uses this technique to automatically log on to compromised hosts and continue encryption after a safe mode boot. If confirmed malicious, this could allow attackers to maintain persistence and further encrypt the network, leading to significant data loss and operational disruption.

## MITRE ATT&CK

- T1552.002

## Analytic Stories

- BlackMatter Ransomware

## Data Sources

- Sysmon EventID 12
- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552.002/autoadminlogon/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/add_defaultuser_and_password_in_registry.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
