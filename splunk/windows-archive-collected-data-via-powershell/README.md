# Windows Archive Collected Data via Powershell

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the use of PowerShell scripts to archive files into a temporary folder. It leverages PowerShell Script Block Logging, specifically monitoring for the `Compress-Archive` command targeting the `Temp` directory. This activity is significant as it may indicate an adversary's attempt to collect and compress data for exfiltration. If confirmed malicious, this behavior could lead to unauthorized data access and exfiltration, posing a severe risk to sensitive information and overall network security.

## MITRE ATT&CK

- T1560

## Analytic Stories

- APT37 Rustonotto and FadeStealer
- CISA AA23-347A

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1560/powershell_archive/powershell_archive.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_archive_collected_data_via_powershell.yml)*
