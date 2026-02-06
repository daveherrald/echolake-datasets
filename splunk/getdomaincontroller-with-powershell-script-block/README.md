# GetDomainController with PowerShell Script Block

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of the `Get-DomainController` commandlet using PowerShell Script Block Logging (EventCode=4104). This commandlet is part of PowerView, a tool often used for domain enumeration. The detection leverages script block text to identify this specific activity. Monitoring this behavior is crucial as it may indicate an adversary or Red Team performing reconnaissance to map out domain controllers. If confirmed malicious, this activity could lead to further domain enumeration, potentially exposing sensitive information and aiding in lateral movement within the network.

## MITRE ATT&CK

- T1018

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/getdc.log


---

*Source: [Splunk Security Content](detections/endpoint/getdomaincontroller_with_powershell_script_block.yml)*
