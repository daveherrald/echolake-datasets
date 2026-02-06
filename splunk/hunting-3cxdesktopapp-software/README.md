# Hunting 3CXDesktopApp Software

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the presence of any version of the 3CXDesktopApp, also known as the 3CX Desktop App, on Mac or Windows systems. It leverages the Endpoint data model's Processes node to identify instances of the application running, although it does not provide file version information. This activity is significant because 3CX has identified vulnerabilities in versions 18.12.407 and 18.12.416, which could be exploited by attackers. If confirmed malicious, this could lead to unauthorized access, data exfiltration, or further compromise of the affected systems.

## MITRE ATT&CK

- T1195.002

## Analytic Stories

- 3CX Supply Chain Attack

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1195.002/3CX/3cx_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/hunting_3cxdesktopapp_software.yml)*
