# Windows Find Domain Organizational Units with GetDomainOU

**Type:** TTP

**Author:** Gowthamaraj Rajendran, Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of the `Get-DomainOU` cmdlet, a part of the PowerView toolkit used for Windows domain enumeration. It leverages PowerShell Script Block Logging (EventCode=4104) to identify this activity. Detecting `Get-DomainOU` usage is significant as adversaries may use it to gather information about organizational units within Active Directory, which can facilitate lateral movement or privilege escalation. If confirmed malicious, this activity could allow attackers to map the domain structure, aiding in further exploitation and persistence within the network.

## MITRE ATT&CK

- T1087.002

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/AD_discovery/windows-powershell-DomainOU-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_find_domain_organizational_units_with_getdomainou.yml)*
