# Dump LSASS via comsvcs DLL

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting the behavior of dumping credentials from memory by exploiting the Local Security Authority Subsystem Service (LSASS) using the comsvcs.dll and MiniDump via rundll32. This detection leverages process information from Endpoint Detection and Response (EDR) logs, focusing on specific command-line executions. This activity is significant because it indicates potential credential theft, which can lead to broader system compromise, persistence, lateral movement, and privilege escalation. If confirmed malicious, attackers could gain unauthorized access to sensitive information, leading to data theft, ransomware attacks, or other damaging outcomes.

## MITRE ATT&CK

- T1003.001

## Analytic Stories

- Living Off The Land
- CISA AA22-257A
- Volt Typhoon
- HAFNIUM Group
- Prestige Ransomware
- Suspicious Rundll32 Activity
- Industroyer2
- Data Destruction
- Flax Typhoon
- CISA AA22-264A
- Compromised Windows Host
- Credential Dumping
- Scattered Lapsus$ Hunters
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/dump_lsass_via_comsvcs_dll.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
