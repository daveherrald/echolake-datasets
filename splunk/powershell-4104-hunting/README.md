# PowerShell 4104 Hunting

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies suspicious PowerShell execution using Script Block Logging (EventCode 4104). It leverages specific patterns and keywords within the ScriptBlockText field to detect potentially malicious activities. This detection is significant for SOC analysts as PowerShell is commonly used by attackers for various malicious purposes, including code execution, privilege escalation, and persistence. If confirmed malicious, this activity could allow attackers to execute arbitrary commands, exfiltrate data, or maintain long-term access to the compromised system, posing a severe threat to the organization's security.

## MITRE ATT&CK

- T1059.001

## Analytic Stories

- Braodo Stealer
- Cactus Ransomware
- China-Nexus Threat Activity
- CISA AA23-347A
- CISA AA24-241A
- Cleo File Transfer Software
- DarkGate Malware
- Data Destruction
- Flax Typhoon
- Hermetic Wiper
- Lumma Stealer
- Malicious PowerShell
- Medusa Ransomware
- Rhysida Ransomware
- Salt Typhoon
- SystemBC
- PHP-CGI RCE Attack on Japanese Organizations
- Water Gamayun
- XWorm
- Scattered Spider
- Interlock Ransomware
- 0bj3ctivity Stealer
- APT37 Rustonotto and FadeStealer
- GhostRedirector IIS Module and Rungan Backdoor
- Hellcat Ransomware
- Microsoft WSUS CVE-2025-59287

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/sbl_xml.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_4104_hunting.yml)*
