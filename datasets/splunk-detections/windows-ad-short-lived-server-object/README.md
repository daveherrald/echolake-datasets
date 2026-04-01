# Windows AD Short Lived Server Object

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying the creation and quick deletion of a Domain Controller (DC) object within 30 seconds in an Active Directory environment, indicative of a potential DCShadow attack. This detection leverages Windows Security Event Codes 5137 and 5141, analyzing the duration between these events. This activity is significant as DCShadow allows attackers with privileged access to register a rogue DC, enabling unauthorized changes to AD objects, including credentials. If confirmed malicious, this could lead to unauthorized AD modifications, compromising the integrity and security of the entire domain.

## MITRE ATT&CK

- T1207

## Analytic Stories

- Compromised Windows Host
- Sneaky Active Directory Persistence Tricks

## Data Sources

- Windows Event Log Security 5137
- Windows Event Log Security 5141

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1207/short_lived_server_object/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_short_lived_server_object.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
