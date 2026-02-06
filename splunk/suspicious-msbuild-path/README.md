# Suspicious msbuild path

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of msbuild.exe from a non-standard path. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs that deviate from typical msbuild.exe locations. This activity is significant because msbuild.exe is commonly abused by attackers to execute malicious code, and running it from an unusual path can indicate an attempt to evade detection. If confirmed malicious, this behavior could allow an attacker to execute arbitrary code, potentially leading to system compromise and further malicious activities.

## MITRE ATT&CK

- T1036.003
- T1127.001

## Analytic Stories

- Trusted Developer Utilities Proxy Execution MSBuild
- Masquerading - Rename System Utilities
- Living Off The Land
- Cobalt Strike
- BlackByte Ransomware
- Graceful Wipe Out Attack
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

*Source: [Splunk Security Content](detections/endpoint/suspicious_msbuild_path.yml)*
