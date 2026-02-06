# Windows Vulnerable Driver Installed

**Type:** TTP

**Author:** Dean Luxton

## Description

The following analytic detects the loading of known vulnerable Windows drivers, which may indicate potential persistence or privilege escalation attempts. It leverages Windows System service install EventCode 7045 to identify driver loading events and cross-references them with a list of vulnerable drivers. This activity is significant as attackers often exploit vulnerable drivers to gain elevated privileges or maintain persistence on a system. If confirmed malicious, this could allow attackers to execute arbitrary code with high privileges, leading to further system compromise and potential data exfiltration. This detection is a Windows Event Log adaptation of the Sysmon driver loaded detection written by Michael Haag.

## MITRE ATT&CK

- T1543.003

## Analytic Stories

- Windows Drivers

## Data Sources

- Windows Event Log System 7045

## Sample Data

- **Source:** XmlWinEventLog:System
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1014/windows-system.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_vulnerable_driver_installed.yml)*
