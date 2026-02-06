# Malicious PowerShell Process - Encoded Command

**Type:** Hunting

**Author:** David Dorsey, Michael Haag, Splunk, SirDuckly, GitHub Community

## Description

The following analytic detects the use of the EncodedCommand parameter in PowerShell processes. It leverages Endpoint Detection and Response (EDR) data to identify variations of the EncodedCommand parameter, including shortened forms and different command switch types. This activity is significant because adversaries often use encoded commands to obfuscate malicious scripts, making detection harder. If confirmed malicious, this behavior could allow attackers to execute hidden code, potentially leading to unauthorized access, privilege escalation, or persistent threats within the environment. Review parallel events to determine legitimacy and tune based on known administrative scripts.

## MITRE ATT&CK

- T1027

## Analytic Stories

- CISA AA22-320A
- Hermetic Wiper
- Sandworm Tools
- Qakbot
- Volt Typhoon
- NOBELIUM Group
- Data Destruction
- Lumma Stealer
- Malicious PowerShell
- DarkCrystal RAT
- WhisperGate
- Crypto Stealer
- Microsoft SharePoint Vulnerabilities
- Scattered Spider
- GhostRedirector IIS Module and Rungan Backdoor
- Microsoft WSUS CVE-2025-59287

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1027/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/malicious_powershell_process___encoded_command.yml)*
