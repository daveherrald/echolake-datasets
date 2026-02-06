# Malicious PowerShell Process With Obfuscation Techniques

**Type:** TTP

**Author:** David Dorsey, Splunk

## Description

The following analytic detects PowerShell processes launched with command-line arguments indicative of obfuscation techniques. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names, parent processes, and complete command-line executions. This activity is significant because obfuscated PowerShell commands are often used by attackers to evade detection and execute malicious scripts. If confirmed malicious, this activity could lead to unauthorized code execution, privilege escalation, or persistent access within the environment, posing a significant security risk.

## MITRE ATT&CK

- T1059.001

## Analytic Stories

- Malicious PowerShell
- Hermetic Wiper
- Data Destruction
- GhostRedirector IIS Module and Rungan Backdoor
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 1

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/obfuscated_powershell/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/malicious_powershell_process_with_obfuscation_techniques.yml)*
