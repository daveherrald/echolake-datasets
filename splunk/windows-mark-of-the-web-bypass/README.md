# Windows Mark Of The Web Bypass

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies a suspicious process that deletes the Mark-of-the-Web (MOTW) data stream. It leverages Sysmon EventCode 23 to detect when a file's Zone.Identifier stream is removed. This activity is significant because it is a common technique used by malware, such as Ave Maria RAT, to bypass security restrictions on files downloaded from the internet. If confirmed malicious, this behavior could allow an attacker to execute potentially harmful files without triggering security warnings, leading to further compromise of the system.

## MITRE ATT&CK

- T1553.005

## Analytic Stories

- Quasar RAT
- Warzone RAT

## Data Sources

- Sysmon EventID 23

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1553.005/mark_of_the_web_bypass/possible-motw-deletion.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_mark_of_the_web_bypass.yml)*
