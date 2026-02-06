# Suspicious microsoft workflow compiler rename

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the renaming of microsoft.workflow.compiler.exe, a rarely used executable typically located in C:\Windows\Microsoft.NET\Framework64\v4.0.30319. This detection leverages Endpoint Detection and Response (EDR) data, focusing on process names and original file names. This activity is significant because renaming this executable can indicate an attempt to evade security controls. If confirmed malicious, an attacker could use this renamed executable to execute arbitrary code, potentially leading to privilege escalation or persistent access within the environment.

## MITRE ATT&CK

- T1036.003
- T1127

## Analytic Stories

- Masquerading - Rename System Utilities
- Living Off The Land
- Cobalt Strike
- Trusted Developer Utilities Proxy Execution
- BlackByte Ransomware
- Graceful Wipe Out Attack

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1127/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_microsoft_workflow_compiler_rename.yml)*
