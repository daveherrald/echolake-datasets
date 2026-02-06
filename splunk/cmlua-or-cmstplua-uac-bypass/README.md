# CMLUA Or CMSTPLUA UAC Bypass

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the use of COM objects like CMLUA or CMSTPLUA to bypass User Account Control (UAC). It leverages Sysmon EventCode 7 to identify the loading of specific DLLs (CMLUA.dll, CMSTPLUA.dll, CMLUAUTIL.dll) by processes not typically associated with these libraries. This activity is significant as it indicates an attempt to gain elevated privileges, a common tactic used by ransomware adversaries. If confirmed malicious, this could allow attackers to execute code with administrative rights, leading to potential system compromise and further malicious activities.

## MITRE ATT&CK

- T1218.003

## Analytic Stories

- DarkSide Ransomware
- Ransomware
- LockBit Ransomware
- ValleyRAT

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/darkside_cmstp_com/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/cmlua_or_cmstplua_uac_bypass.yml)*
