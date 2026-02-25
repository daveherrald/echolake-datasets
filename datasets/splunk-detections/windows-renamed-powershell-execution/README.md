# Windows Renamed Powershell Execution

**Type:** TTP

**Author:** Teoderick Contreras, Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for identifying instances where the PowerShell executable has been renamed and executed under an alternate filename. This behavior is commonly associated with attempts to evade security controls or bypass logging mechanisms that monitor standard PowerShell usage. While rare in legitimate environments, renamed PowerShell binaries are frequently observed in malicious campaigns leveraging Living-off-the-Land Binaries (LOLBins) and fileless malware techniques. This detection flags executions of PowerShell where the process name does not match the default powershell.exe or pwsh.exe, especially when invoked from unusual paths or accompanied by suspicious command-line arguments.

## MITRE ATT&CK

- T1036.003

## Analytic Stories

- XWorm
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 1

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036.003/renamed_powershell/renamed_powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_renamed_powershell_execution.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
