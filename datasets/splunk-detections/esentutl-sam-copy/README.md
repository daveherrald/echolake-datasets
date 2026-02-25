# Esentutl SAM Copy

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the use of `esentutl.exe` to access credentials stored in the ntds.dit or SAM file. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs that include command-line details. This activity is significant because it may indicate an attempt to extract sensitive credential information, which is a common tactic in lateral movement and privilege escalation. If confirmed malicious, this could allow an attacker to gain unauthorized access to user credentials, potentially compromising the entire network.

## MITRE ATT&CK

- T1003.002

## Analytic Stories

- Credential Dumping
- Living Off The Land

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.002/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/esentutl_sam_copy.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
