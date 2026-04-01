# Windows MSIExec Unregister DLLRegisterServer

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the use of msiexec.exe with the /z switch parameter, which is used to unload DLLRegisterServer. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs, including command-line arguments. This activity is significant because unloading DLLRegisterServer can be indicative of an attempt to deregister a DLL, potentially disrupting legitimate services or hiding malicious activity. If confirmed malicious, this could allow an attacker to disable security controls, evade detection, or disrupt system functionality, leading to further compromise of the environment.

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


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
