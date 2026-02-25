# Powershell COM Hijacking InprocServer32 Modification

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting attempts to modify or add a Component Object Model (COM) entry to the InProcServer32 path within the registry using PowerShell. It leverages PowerShell ScriptBlock Logging (EventCode 4104) to identify suspicious script blocks that target the InProcServer32 registry path. This activity is significant because modifying COM objects can be used for persistence or privilege escalation by attackers. If confirmed malicious, this could allow an attacker to execute arbitrary code or maintain persistent access to the compromised system, posing a severe security risk.

## MITRE ATT&CK

- T1059.001
- T1546.015

## Analytic Stories

- Malicious PowerShell

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.015/atomic_red_team/windows-powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_com_hijacking_inprocserver32_modification.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
