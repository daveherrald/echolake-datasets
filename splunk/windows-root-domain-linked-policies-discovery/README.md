# Windows Root Domain linked policies Discovery

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the use of the `[Adsisearcher]` type accelerator in PowerShell to query Active Directory for root domain linked policies. It leverages PowerShell Script Block Logging (EventCode=4104) to identify this activity. This behavior is significant as it may indicate an attempt by adversaries or Red Teams to gain situational awareness and perform Active Directory Discovery. If confirmed malicious, this activity could allow attackers to map out domain policies, potentially aiding in further exploitation or lateral movement within the network.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/adsi_discovery/windows-powershell-xml1.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_root_domain_linked_policies_discovery.yml)*
