# Credential Dumping via Copy Command from Shadow Copy

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting the use of the copy command to dump credentials from a shadow copy. It leverages Endpoint Detection and Response (EDR) data to identify processes with command lines referencing critical files like "sam", "security", "system", and "ntds.dit" in system directories. This activity is significant as it indicates an attempt to extract credentials, a common technique for unauthorized access and privilege escalation. If confirmed malicious, this could lead to attackers gaining sensitive login information, escalating privileges, moving laterally within the network, or accessing sensitive data.

## MITRE ATT&CK

- T1003.003

## Analytic Stories

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


---

*Source: [Splunk Security Content](detections/endpoint/credential_dumping_via_copy_command_from_shadow_copy.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
