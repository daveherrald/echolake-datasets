# Windows PowerShell Script Block With Malicious String

**Type:** TTP

**Author:** Steven Dick

## Description

This dataset contains sample data for detecting the execution of multiple offensive toolkits and commands by leveraging PowerShell Script Block Logging (EventCode=4104). This method captures and logs the full command sent to PowerShell, allowing for the identification of suspicious activities including several well-known tools used for credential theft, lateral movement, and persistence. If confirmed malicious, this could lead to unauthorized access, privilege escalation, and potential compromise of sensitive information within the environment.

## MITRE ATT&CK

- T1059.001

## Analytic Stories

- Malicious PowerShell

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552.006/powershell_gpp_discovery/win-powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powershell_script_block_with_malicious_string.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
