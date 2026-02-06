# Windows Wmic Systeminfo Discovery

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of Windows Management Instrumentation Command-line (WMIC) commands used for computer system discovery on a Windows system. Specifically, it monitors for commands such as “wmic computersystem” that retrieve detailed information about the computer’s model, manufacturer, name, domain, and other system attributes. While these commands are commonly used by administrators for inventory and troubleshooting, they may also be exploited by adversaries to gain insight into the target environment during the reconnaissance phase of an attack. Identifying and alerting on WMIC computer system queries helps security teams recognize unauthorized information gathering and take steps to mitigate potential threats.

## MITRE ATT&CK

- T1082

## Analytic Stories

- LAMEHUG

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/lamehug/T1082/wmic_cmd/wmic_cmd.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_wmic_systeminfo_discovery.yml)*
