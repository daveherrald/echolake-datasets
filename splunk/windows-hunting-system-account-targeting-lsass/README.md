# Windows Hunting System Account Targeting Lsass

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies processes attempting to access Lsass.exe, which may indicate credential dumping or applications needing credential access. It leverages Sysmon EventCode 10 to detect such activities by analyzing fields like TargetImage, GrantedAccess, and SourceImage. This behavior is significant as unauthorized access to Lsass.exe can lead to credential theft, posing a severe security risk. If confirmed malicious, attackers could gain access to sensitive credentials, potentially leading to privilege escalation and further compromise of the environment.

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

*Source: [Splunk Security Content](detections/endpoint/windows_hunting_system_account_targeting_lsass.yml)*
