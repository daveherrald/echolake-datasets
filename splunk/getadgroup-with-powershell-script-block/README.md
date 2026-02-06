# GetAdGroup with PowerShell Script Block

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of the `Get-AdGroup` PowerShell cmdlet using PowerShell Script Block Logging (EventCode=4104). This cmdlet is used to enumerate all domain groups, which adversaries may exploit for situational awareness and Active Directory discovery. Monitoring this activity is crucial as it can indicate reconnaissance efforts within the network. If confirmed malicious, this behavior could lead to further exploitation, such as privilege escalation or lateral movement, by providing attackers with detailed information about the domain's group structure.

## MITRE ATT&CK

- T1069.002

## Analytic Stories

- Scattered Lapsus$ Hunters
- Active Directory Discovery

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.002/AD_discovery/windows-powershell-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/getadgroup_with_powershell_script_block.yml)*
