# Windows Vulnerable 3CX Software

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects instances of the 3CXDesktopApp.exe with a FileVersion of 18.12.x, leveraging Sysmon logs. This detection focuses on identifying vulnerable versions 18.12.407 and 18.12.416 of the 3CX desktop app. Monitoring this activity is crucial as these specific versions have known vulnerabilities that could be exploited by attackers. If confirmed malicious, exploitation of this vulnerability could lead to unauthorized access, code execution, or further compromise of the affected system, posing significant security risks.

## MITRE ATT&CK

- T1195.002

## Analytic Stories

- 3CX Supply Chain Attack

## Data Sources

- Sysmon EventID 1

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1195.002/3CX/3cx_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_vulnerable_3cx_software.yml)*
