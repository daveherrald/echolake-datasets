# Windows Odbcconf Load DLL

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of odbcconf.exe with the regsvr action to load a DLL. This is identified by monitoring command-line arguments in process creation logs from Endpoint Detection and Response (EDR) agents. This activity is significant as it may indicate an attempt to execute arbitrary code via DLL loading, a common technique used in various attack vectors. If confirmed malicious, this could allow an attacker to execute code with the privileges of the odbcconf.exe process, potentially leading to system compromise or further lateral movement.

## MITRE ATT&CK

- T1218.008

## Analytic Stories

- Living Off The Land

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.008/atomic_red_team/windows-sysmon-odbc-regsvr.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_odbcconf_load_dll.yml)*
