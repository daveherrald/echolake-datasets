# MSBuild Suspicious Spawned By Script Process

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the suspicious spawning of MSBuild.exe by Windows Script Host processes (cscript.exe or wscript.exe). This behavior is often associated with malware or adversaries executing malicious MSBuild processes via scripts on compromised hosts. The detection leverages Endpoint Detection and Response (EDR) telemetry, focusing on process creation events where MSBuild is a child of script hosts. This activity is significant as it may indicate an attempt to execute malicious code. If confirmed malicious, it could lead to unauthorized code execution, potentially compromising the host and allowing further malicious activities.

## MITRE ATT&CK

- T1127.001

## Analytic Stories

- Trusted Developer Utilities Proxy Execution MSBuild
- Storm-2460 CLFS Zero Day Exploitation

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1127.001/regsvr32_silent/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/msbuild_suspicious_spawned_by_script_process.yml)*
