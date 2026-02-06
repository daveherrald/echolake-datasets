# Windows Screen Capture Via Powershell

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of a PowerShell script designed to capture screen images on a host. It leverages PowerShell Script Block Logging to identify specific script block text patterns associated with screen capture activities. This behavior is significant as it may indicate an attempt to exfiltrate sensitive information by capturing desktop screenshots. If confirmed malicious, this activity could allow an attacker to gather visual data from the compromised system, potentially leading to data breaches or further exploitation.

## MITRE ATT&CK

- T1113

## Analytic Stories

- APT37 Rustonotto and FadeStealer
- Winter Vivern
- Water Gamayun

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/winter-vivern/pwh_exfiltration/windows-powershell-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_screen_capture_via_powershell.yml)*
