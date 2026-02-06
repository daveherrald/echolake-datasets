# Powershell Windows Defender Exclusion Commands

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the use of PowerShell commands to add or set Windows Defender exclusions. It leverages EventCode 4104 to identify suspicious `Add-MpPreference` or `Set-MpPreference` commands with exclusion parameters. This activity is significant because adversaries often use it to bypass Windows Defender, allowing malicious code to execute without detection. If confirmed malicious, this behavior could enable attackers to evade antivirus defenses, maintain persistence, and execute further malicious activities undetected.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- CISA AA22-320A
- AgentTesla
- Remcos
- Windows Defense Evasion Tactics
- Data Destruction
- WhisperGate
- Warzone RAT
- NetSupport RMM Tool Abuse

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/powershell_windows_defender_exclusion_commands/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_windows_defender_exclusion_commands.yml)*
