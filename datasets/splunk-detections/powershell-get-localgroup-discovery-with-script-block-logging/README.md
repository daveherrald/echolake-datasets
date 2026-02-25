# Powershell Get LocalGroup Discovery with Script Block Logging

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of the PowerShell cmdlet `get-localgroup` using PowerShell Script Block Logging (EventCode=4104). This method captures the full command sent to PowerShell, providing detailed visibility into script execution. Monitoring this activity is significant as it can indicate an attempt to enumerate local groups, which may be a precursor to privilege escalation or lateral movement. If confirmed malicious, an attacker could gain insights into group memberships, potentially leading to unauthorized access or privilege abuse. Review parallel processes and the entire script block for comprehensive analysis.

## MITRE ATT&CK

- T1069.001

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/getlocalgroup.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_get_localgroup_discovery_with_script_block_logging.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
