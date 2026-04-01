# Suspicious MSBuild Rename

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of renamed instances of msbuild.exe. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and original file names within the Endpoint data model. This activity is significant because msbuild.exe is a legitimate tool often abused by attackers to execute malicious code while evading detection. If confirmed malicious, this behavior could allow an attacker to execute arbitrary code, potentially leading to system compromise, data exfiltration, or further lateral movement within the network.

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

*Source: [Splunk Security Content](detections/endpoint/suspicious_msbuild_rename.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
