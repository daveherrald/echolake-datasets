# Windows Odbcconf Hunting

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies the execution of Odbcconf.exe within the environment. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events where the process name is Odbcconf.exe. This activity is significant because Odbcconf.exe can be used by attackers to execute arbitrary commands or load malicious DLLs, potentially leading to code execution or persistence. If confirmed malicious, this behavior could allow an attacker to maintain access to the system, execute further malicious activities, or escalate privileges, posing a significant threat to the environment.

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

*Source: [Splunk Security Content](detections/endpoint/windows_odbcconf_hunting.yml)*
