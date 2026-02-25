# Credential Dumping via Symlink to Shadow Copy

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting the creation of a symlink to a shadow copy, which may indicate credential dumping attempts. It leverages the Endpoint.Processes data model in Splunk to identify processes executing commands containing "mklink" and "HarddiskVolumeShadowCopy". This activity is significant because attackers often use this technique to manipulate or delete shadow copies, hindering system backup and recovery efforts. If confirmed malicious, this could prevent data restoration, complicate incident response, and lead to data loss or compromise. Analysts should review the process details, user, parent process, and any related artifacts to identify the attack source.

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

*Source: [Splunk Security Content](detections/endpoint/credential_dumping_via_symlink_to_shadow_copy.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
