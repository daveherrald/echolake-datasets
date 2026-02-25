# BITSAdmin Download File

**Type:** TTP

**Author:** Michael Haag, Sittikorn S

## Description

This dataset contains sample data for detecting the use of `bitsadmin.exe` with the `transfer` parameter to download a remote object. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and command-line telemetry. This activity is significant because `bitsadmin.exe` can be exploited to download and execute malicious files without immediate detection. If confirmed malicious, an attacker could use this technique to download and execute payloads, potentially leading to code execution, privilege escalation, or persistent access within the environment. Review parallel and child processes, especially `svchost.exe`, for associated artifacts.

## MITRE ATT&CK

- T1197
- T1105

## Analytic Stories

- Ingress Tool Transfer
- BITS Jobs
- DarkSide Ransomware
- Living Off The Land
- Flax Typhoon
- Gozi Malware
- Scattered Spider
- APT37 Rustonotto and FadeStealer
- GhostRedirector IIS Module and Rungan Backdoor
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1197/atomic_red_team/windows-sysmon.log

- **Source:** crowdstrike
  **Sourcetype:** crowdstrike:events:sensor
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1197/atomic_red_team/crowdstrike_falcon.log


---

*Source: [Splunk Security Content](detections/endpoint/bitsadmin_download_file.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
