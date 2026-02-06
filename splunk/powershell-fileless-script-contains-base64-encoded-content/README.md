# Powershell Fileless Script Contains Base64 Encoded Content

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of PowerShell scripts containing Base64 encoded content, specifically identifying the use of `FromBase64String`. It leverages PowerShell Script Block Logging (EventCode=4104) to capture and analyze the full command sent to PowerShell. This activity is significant as Base64 encoding is often used by attackers to obfuscate malicious payloads, making it harder to detect. If confirmed malicious, this could lead to code execution, allowing attackers to run arbitrary commands and potentially compromise the system.

## MITRE ATT&CK

- T1027
- T1059.001

## Analytic Stories

- Winter Vivern
- Malicious PowerShell
- Medusa Ransomware
- Data Destruction
- NjRAT
- AsyncRAT
- Hermetic Wiper
- IcedID
- XWorm
- 0bj3ctivity Stealer
- APT37 Rustonotto and FadeStealer
- GhostRedirector IIS Module and Rungan Backdoor
- Hellcat Ransomware
- Microsoft WSUS CVE-2025-59287
- NetSupport RMM Tool Abuse

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/frombase64string.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_fileless_script_contains_base64_encoded_content.yml)*
