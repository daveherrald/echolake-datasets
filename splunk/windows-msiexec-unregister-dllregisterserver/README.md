# Windows MSIExec Unregister DLLRegisterServer

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the use of msiexec.exe with the /z switch parameter, which is used to unload DLLRegisterServer. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs, including command-line arguments. This activity is significant because unloading DLLRegisterServer can be indicative of an attempt to deregister a DLL, potentially disrupting legitimate services or hiding malicious activity. If confirmed malicious, this could allow an attacker to disable security controls, evade detection, or disrupt system functionality, leading to further compromise of the environment.

## MITRE ATT&CK

- T1218.007

## Analytic Stories

- Windows System Binary Proxy Execution MSIExec

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.007/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_msiexec_unregister_dllregisterserver.yml)*
