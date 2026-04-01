# Windows PowerShell Disable HTTP Logging

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the use of `get-WebConfigurationProperty` and `Set-ItemProperty` commands in PowerShell to disable HTTP logging on Windows systems. This detection leverages PowerShell Script Block Logging, specifically looking for script blocks that reference HTTP logging properties and attempt to set them to "false" or "dontLog". Disabling HTTP logging is significant as it can be used by adversaries to cover their tracks and delete logs, hindering forensic investigations. If confirmed malicious, this activity could allow attackers to evade detection and persist in the environment undetected.

## MITRE ATT&CK

- T1505.004
- T1562.002

## Analytic Stories

- IIS Components
- Windows Defense Evasion Tactics

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.004/4104_disable_http_logging_windows-powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powershell_disable_http_logging.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
