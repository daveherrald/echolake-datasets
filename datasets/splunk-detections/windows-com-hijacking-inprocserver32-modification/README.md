# Windows COM Hijacking InprocServer32 Modification

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the modification of the InProcServer32 registry key by reg.exe, indicative of potential COM hijacking. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and command-line execution logs. COM hijacking is significant as it allows adversaries to insert malicious code that executes in place of legitimate software, providing a means for persistence. If confirmed malicious, this activity could enable attackers to execute arbitrary code, disrupt legitimate system components, and maintain long-term access to the compromised environment.

## MITRE ATT&CK

- T1546.015

## Analytic Stories

- Living Off The Land
- Compromised Windows Host

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.015/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_com_hijacking_inprocserver32_modification.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
