# Windows Linked Policies In ADSI Discovery

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the use of the `[Adsisearcher]` type accelerator in PowerShell Script Block Logging (EventCode=4104) to query Active Directory for domain organizational units. This detection leverages PowerShell operational logs to identify script blocks containing `[adsisearcher]`, `objectcategory=organizationalunit`, and `findAll()`. This activity is significant as it indicates potential reconnaissance efforts by adversaries to gain situational awareness of the domain structure. If confirmed malicious, this could lead to further exploitation, such as privilege escalation or lateral movement within the network.

## MITRE ATT&CK

- T1087.002

## Analytic Stories

- Data Destruction
- Active Directory Discovery
- Industroyer2

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/adsi_discovery/windows-powershell-xml2.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_linked_policies_in_adsi_discovery.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
