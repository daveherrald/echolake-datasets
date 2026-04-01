# Windows Exfiltration Over C2 Via Powershell UploadString

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying potential data exfiltration using the PowerShell `net.webclient` command with the `UploadString` method. It leverages PowerShell Script Block Logging to detect instances where this command is executed. This activity is significant as it may indicate an attempt to upload sensitive data, such as desktop screenshots or files, to an external or internal URI, often associated with malware like Winter-Vivern. If confirmed malicious, this could lead to unauthorized data transfer, compromising sensitive information and potentially leading to further exploitation of the compromised host.

## MITRE ATT&CK

- T1041

## Analytic Stories

- APT37 Rustonotto and FadeStealer
- Winter Vivern

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/winter-vivern/pwh_uploadstring/windows-powershell-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_exfiltration_over_c2_via_powershell_uploadstring.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
