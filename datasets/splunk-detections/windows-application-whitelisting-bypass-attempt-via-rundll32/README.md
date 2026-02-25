# Windows Application Whitelisting Bypass Attempt via Rundll32

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of rundll32.exe calling one of the following DLLs:

- Advpack.dll
- Ieadvpack.dll
- Syssetup.dll
- Setupapi.dll

with one of the following functions: "LaunchINFSection", "InstallHinfSection", "SetupInfObjectInstallAction".
This method is identified through Endpoint Detection and Response (EDR) telemetry, 
focusing on command-line executions and process details. 
This activity is significant as it indicates a potential application
control or whitelisting bypass, allowing script code execution from a file.
If confirmed malicious, an attacker could execute arbitrary code, potentially leading to privilege escalation,
persistence, or further network compromise.
Investigate the script content, network connections, and any spawned child processes for further context.


## MITRE ATT&CK

- T1218.011

## Analytic Stories

- Suspicious Rundll32 Activity
- Living Off The Land
- Compromised Windows Host

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.011/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_application_whitelisting_bypass_attempt_via_rundll32.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
