# Windows Possible Credential Dumping

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects potential credential dumping by identifying specific GrantedAccess permission requests and CallTrace DLLs targeting the LSASS process. It leverages Sysmon EventCode 10 logs, focusing on access requests to lsass.exe and call traces involving debug and native API DLLs like dbgcore.dll, dbghelp.dll, and ntdll.dll. This activity is significant as credential dumping can lead to unauthorized access to sensitive credentials. If confirmed malicious, attackers could gain elevated privileges and persist within the environment, posing a severe security risk.

## MITRE ATT&CK

- T1003.001

## Analytic Stories

- Detect Zerologon Attack
- CISA AA22-264A
- Credential Dumping
- CISA AA23-347A
- DarkSide Ransomware
- CISA AA22-257A
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 10

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon_creddump.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_possible_credential_dumping.yml)*
