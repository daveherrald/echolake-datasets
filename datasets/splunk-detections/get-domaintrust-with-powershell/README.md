# Get-DomainTrust with PowerShell

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying the execution of the Get-DomainTrust command from PowerView using PowerShell, which is used to gather domain trust information. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and command-line telemetry. This activity is significant as it indicates potential reconnaissance efforts by an adversary to understand domain trust relationships, which can inform lateral movement strategies. If confirmed malicious, this could allow attackers to map out the network, identify potential targets, and plan further attacks, potentially compromising additional systems within the domain.

## MITRE ATT&CK

- T1482

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1482/discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/get_domaintrust_with_powershell.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
