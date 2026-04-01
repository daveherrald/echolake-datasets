# Elevated Group Discovery with PowerView

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of the `Get-DomainGroupMember` cmdlet from PowerView, identified through PowerShell Script Block Logging (EventCode=4104). This cmdlet is used to enumerate members of elevated domain groups such as Domain Admins and Enterprise Admins. Monitoring this activity is crucial as it indicates potential reconnaissance efforts by adversaries to identify high-privileged users within the domain. If confirmed malicious, this activity could lead to targeted attacks on privileged accounts, facilitating further compromise and lateral movement within the network.

## MITRE ATT&CK

- T1069.002

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.002/AD_discovery/windows-powershell-xml-powerview.log

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.002/AD_discovery/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/elevated_group_discovery_with_powerview.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
