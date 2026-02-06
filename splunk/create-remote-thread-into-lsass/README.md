# Create Remote Thread into LSASS

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects the creation of a remote thread in the Local Security Authority Subsystem Service (LSASS). This behavior is identified using Sysmon EventID 8 logs, focusing on processes that create remote threads in lsass.exe. This activity is significant because it is commonly associated with credential dumping, a tactic used by adversaries to steal user authentication credentials. If confirmed malicious, this could allow attackers to gain unauthorized access to sensitive information, leading to potential compromise of the entire network. Analysts should investigate to differentiate between legitimate tools and potential threats.

## MITRE ATT&CK

- T1003.001

## Analytic Stories

- Credential Dumping
- BlackSuit Ransomware
- Lokibot

## Data Sources

- Sysmon EventID 8

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/create_remote_thread_into_lsass.yml)*
