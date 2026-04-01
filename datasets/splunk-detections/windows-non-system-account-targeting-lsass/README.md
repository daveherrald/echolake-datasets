# Windows Non-System Account Targeting Lsass

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying non-SYSTEM accounts requesting access to lsass.exe. This detection leverages Sysmon EventCode 10 logs to monitor access attempts to the Local Security Authority Subsystem Service (lsass.exe) by non-SYSTEM users. This activity is significant as it may indicate credential dumping attempts or unauthorized access to sensitive credentials. If confirmed malicious, an attacker could potentially extract credentials from memory, leading to privilege escalation or lateral movement within the network. Immediate investigation is required to determine the legitimacy of the access request and to mitigate any potential threats.

## MITRE ATT&CK

- T1003.001

## Analytic Stories

- CISA AA23-347A
- Credential Dumping
- Lokibot
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 10

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon_creddump.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_non_system_account_targeting_lsass.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
