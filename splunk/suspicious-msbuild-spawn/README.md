# Suspicious MSBuild Spawn

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies instances where wmiprvse.exe spawns msbuild.exe, which is unusual and indicative of potential misuse of a COM object. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process relationships and command-line executions. This activity is significant because msbuild.exe is typically spawned by devenv.exe during legitimate Visual Studio use, not by wmiprvse.exe. If confirmed malicious, this behavior could indicate an attacker executing arbitrary code or scripts, potentially leading to system compromise or further malicious activities.

## MITRE ATT&CK

- T1127.001

## Analytic Stories

- Trusted Developer Utilities Proxy Execution MSBuild
- Living Off The Land
- Storm-2460 CLFS Zero Day Exploitation

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1127.001/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_msbuild_spawn.yml)*
