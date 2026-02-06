# Windows Forest Discovery with GetForestDomain

**Type:** TTP

**Author:** Gowthamaraj Rajendran, Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of the `Get-ForestDomain` cmdlet, a component of the PowerView toolkit used for Windows domain enumeration. It leverages PowerShell Script Block Logging (EventCode=4104) to identify this activity. Detecting `Get-ForestDomain` is significant because adversaries and Red Teams use it to gather detailed information about Active Directory forest and domain configurations. If confirmed malicious, this activity could enable attackers to understand the domain structure, facilitating lateral movement or privilege escalation within the environment.

## MITRE ATT&CK

- T1087.002

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/AD_discovery/windows-powershell-ForestDomain-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_forest_discovery_with_getforestdomain.yml)*
