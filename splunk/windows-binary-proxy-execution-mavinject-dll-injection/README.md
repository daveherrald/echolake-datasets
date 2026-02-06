# Windows Binary Proxy Execution Mavinject DLL Injection

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the use of mavinject.exe for DLL injection into running processes, identified by specific command-line parameters such as /INJECTRUNNING and /HMODULE. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant because it indicates potential arbitrary code execution, a common tactic for malware deployment and persistence. If confirmed malicious, this could allow attackers to execute unauthorized code, escalate privileges, and maintain persistence within the environment, posing a severe security risk.

## MITRE ATT&CK

- T1218.013

## Analytic Stories

- Living Off The Land

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.013/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_binary_proxy_execution_mavinject_dll_injection.yml)*
