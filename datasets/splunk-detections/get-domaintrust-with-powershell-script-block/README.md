# Get-DomainTrust with PowerShell Script Block

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of the Get-DomainTrust command from PowerView using PowerShell Script Block Logging (EventCode=4104). This method captures the full command sent to PowerShell, allowing for detailed inspection. Identifying this activity is significant because it may indicate an attempt to gather domain trust information, which is often a precursor to lateral movement or privilege escalation. If confirmed malicious, this activity could enable an attacker to map trust relationships within the domain, potentially leading to further exploitation and compromise of additional systems.

## MITRE ATT&CK

- T1482

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/domaintrust.log


---

*Source: [Splunk Security Content](detections/endpoint/get_domaintrust_with_powershell_script_block.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
