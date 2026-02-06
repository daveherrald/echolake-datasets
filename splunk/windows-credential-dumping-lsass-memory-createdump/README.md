# Windows Credential Dumping LSASS Memory Createdump

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the use of CreateDump.exe to perform a process dump. This binary is not native to Windows and is often introduced by third-party applications, including PowerShell 7. The detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names, GUIDs, and complete command-line executions. This activity is significant as it may indicate an attempt to dump LSASS memory, which can be used to extract credentials. If confirmed malicious, this could lead to unauthorized access and lateral movement within the network.

## MITRE ATT&CK

- T1003.001

## Analytic Stories

- Compromised Windows Host
- Credential Dumping
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/createdump_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_credential_dumping_lsass_memory_createdump.yml)*
