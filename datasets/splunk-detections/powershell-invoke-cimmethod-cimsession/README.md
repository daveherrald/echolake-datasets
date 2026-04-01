# PowerShell Invoke CIMMethod CIMSession

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the creation of a New-CIMSession cmdlet followed by the use of the Invoke-CIMMethod cmdlet within PowerShell. It leverages PowerShell Script Block Logging to identify these specific cmdlets in the ScriptBlockText field. This activity is significant because it mirrors the behavior of the Invoke-WMIMethod cmdlet, often used for remote code execution via NTLMv2 pass-the-hash authentication. If confirmed malicious, this could allow an attacker to execute commands remotely, potentially leading to unauthorized access and control over targeted systems.

## MITRE ATT&CK

- T1047

## Analytic Stories

- Scattered Lapsus$ Hunters
- Malicious PowerShell
- Active Directory Lateral Movement

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1047/atomic_red_team/4104-cimmethod-windows-powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_invoke_cimmethod_cimsession.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
