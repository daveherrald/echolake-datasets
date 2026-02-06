# Windows Regsvr32 Renamed Binary

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies instances where the regsvr32.exe binary has been renamed and executed. This detection leverages Endpoint Detection and Response (EDR) data, specifically focusing on the original filename metadata. Renaming regsvr32.exe is significant as it can be an evasion technique used by attackers to bypass security controls. If confirmed malicious, this activity could allow an attacker to execute arbitrary DLLs, potentially leading to code execution, privilege escalation, or persistence within the environment.

## MITRE ATT&CK

- T1218.010

## Analytic Stories

- Qakbot
- Compromised Windows Host

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/qakbot/qbot_3/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_regsvr32_renamed_binary.yml)*
