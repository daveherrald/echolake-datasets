# Windows Suspicious VMWare Tools Child Process

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

The following analytic identifies child processes spawned by vmtoolsd.exe, the VMWare Tools service in Windows, which typically runs with SYSTEM privileges. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and parent process relationships. Monitoring this activity is crucial as it can indicate exploitation attempts, such as CVE-2023-20867. If confirmed malicious, attackers could gain SYSTEM-level access, allowing them to execute arbitrary code, escalate privileges, and potentially compromise the entire system.

## MITRE ATT&CK

- T1059

## Analytic Stories

- ESXi Post Compromise
- China-Nexus Threat Activity

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/vmtoolsd/vmtoolsd_execution.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_suspicious_vmware_tools_child_process.yml)*
