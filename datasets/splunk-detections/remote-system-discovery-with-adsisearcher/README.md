# Remote System Discovery with Adsisearcher

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the use of the `[Adsisearcher]` type accelerator in PowerShell scripts to query Active Directory for domain computers. It leverages PowerShell Script Block Logging (EventCode=4104) to identify specific script blocks containing `adsisearcher` and `objectcategory=computer` with methods like `findAll()` or `findOne()`. This activity is significant as it may indicate an attempt by adversaries or Red Teams to perform Active Directory discovery and gain situational awareness. If confirmed malicious, this could lead to further reconnaissance and potential lateral movement within the network.

## MITRE ATT&CK

- T1018

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/AD_discovery/adsisearcher-powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/remote_system_discovery_with_adsisearcher.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
