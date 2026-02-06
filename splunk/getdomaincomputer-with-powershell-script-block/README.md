# GetDomainComputer with PowerShell Script Block

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of the `Get-DomainComputer` commandlet using PowerShell Script Block Logging (EventCode=4104). This commandlet is part of PowerView, a tool often used for enumerating domain computers within Windows environments. The detection leverages script block text analysis to identify this specific command. Monitoring this activity is crucial as it can indicate an adversary's attempt to gather information about domain computers, which is a common step in Active Directory reconnaissance. If confirmed malicious, this activity could lead to further network enumeration and potential lateral movement within the domain.

## MITRE ATT&CK

- T1018

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/sbl_xml.log


---

*Source: [Splunk Security Content](detections/endpoint/getdomaincomputer_with_powershell_script_block.yml)*
