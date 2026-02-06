# WinRAR Spawning Shell Application

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of Windows shell processes initiated by WinRAR, such as "cmd.exe", "powershell.exe", "certutil.exe", "mshta.exe", or "bitsadmin.exe". This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and parent process relationships. This activity is significant because it may indicate exploitation of the WinRAR CVE-2023-38831 vulnerability, where malicious scripts are executed from spoofed ZIP archives. If confirmed malicious, this could lead to unauthorized access, financial loss, and further malicious activities like data theft or ransomware attacks.

## MITRE ATT&CK

- T1105

## Analytic Stories

- Compromised Windows Host
- WinRAR Spoofing Attack CVE-2023-38831

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/atomic_red_team/winrar.log


---

*Source: [Splunk Security Content](detections/endpoint/winrar_spawning_shell_application.yml)*
