# BCDEdit Failure Recovery Modification

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects modifications to the Windows error recovery boot configurations using bcdedit.exe with flags such as "recoveryenabled" and "no". It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names, parent processes, and command-line executions. This activity is significant because ransomware often disables recovery options to prevent system restoration, making it crucial for SOC analysts to investigate. If confirmed malicious, this could hinder recovery efforts, allowing ransomware to cause extensive damage and complicate remediation.

## MITRE ATT&CK

- T1490

## Analytic Stories

- Ransomware
- Compromised Windows Host
- Ryuk Ransomware
- Storm-2460 CLFS Zero Day Exploitation

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1490/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/bcdedit_failure_recovery_modification.yml)*
