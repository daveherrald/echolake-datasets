# Creation of Shadow Copy

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting the creation of shadow copies using Vssadmin or Wmic. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs that include command-line details. This activity is significant because creating shadow copies can be a precursor to ransomware attacks or data exfiltration, allowing attackers to bypass file locks and access sensitive data. If confirmed malicious, this behavior could enable attackers to maintain persistence, recover deleted files, or prepare for further malicious activities, posing a significant risk to the integrity and confidentiality of the system.

## MITRE ATT&CK

- T1003.003

## Analytic Stories

- Volt Typhoon
- Compromised Windows Host
- Credential Dumping

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.003/atomic_red_team/windows-sysmon.log

- **Source:** crowdstrike
  **Sourcetype:** crowdstrike:events:sensor
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.003/atomic_red_team/crowdstrike_falcon.log


---

*Source: [Splunk Security Content](detections/endpoint/creation_of_shadow_copy.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
