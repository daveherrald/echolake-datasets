# Ntdsutil Export NTDS

**Type:** TTP

**Author:** Michael Haag, Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting the use of Ntdsutil to export the Active Directory database (NTDS.dit). It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. This activity is significant because exporting NTDS.dit can be a precursor to offline password cracking, posing a severe security risk. If confirmed malicious, an attacker could gain access to sensitive credentials, potentially leading to unauthorized access and privilege escalation within the network.

## MITRE ATT&CK

- T1003.003

## Analytic Stories

- Credential Dumping
- HAFNIUM Group
- Living Off The Land
- Prestige Ransomware
- Volt Typhoon
- Rhysida Ransomware
- NetSupport RMM Tool Abuse

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.003/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/ntdsutil_export_ntds.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
