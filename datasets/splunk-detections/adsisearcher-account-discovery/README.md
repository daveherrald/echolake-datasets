# AdsiSearcher Account Discovery

**Type:** TTP

**Author:** Teoderick Contreras, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the use of the `[Adsisearcher]` type accelerator in PowerShell to query Active Directory for domain users. It leverages PowerShell Script Block Logging (EventCode=4104) to identify script blocks containing `[adsisearcher]`, `objectcategory=user`, and `.findAll()`. This activity is significant as it may indicate an attempt by adversaries or Red Teams to enumerate domain users for situational awareness and Active Directory discovery. If confirmed malicious, this could lead to further reconnaissance, privilege escalation, or lateral movement within the network.

## MITRE ATT&CK

- T1087.002

## Analytic Stories

- Industroyer2
- Active Directory Discovery
- CISA AA23-347A
- Data Destruction
- Scattered Lapsus$ Hunters

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/AD_discovery/adsisearcher_powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/adsisearcher_account_discovery.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
