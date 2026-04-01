# Windows Exfiltration Over C2 Via Invoke RestMethod

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting potential data exfiltration using PowerShell's Invoke-RestMethod. It leverages PowerShell Script Block Logging to identify scripts that attempt to upload files via HTTP POST requests. This activity is significant as it may indicate an attacker is exfiltrating sensitive data, such as desktop screenshots or files, to an external command and control (C2) server. If confirmed malicious, this could lead to data breaches, loss of sensitive information, and further compromise of the affected systems. Immediate investigation is recommended to determine the intent and scope of the activity.

## MITRE ATT&CK

- T1041

## Analytic Stories

- Microsoft WSUS CVE-2025-59287
- Hellcat Ransomware
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

*Source: [Splunk Security Content](detections/endpoint/windows_exfiltration_over_c2_via_invoke_restmethod.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
