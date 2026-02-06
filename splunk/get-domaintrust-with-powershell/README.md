# Get-DomainTrust with PowerShell

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies the execution of the Get-DomainTrust command from PowerView using PowerShell, which is used to gather domain trust information. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and command-line telemetry. This activity is significant as it indicates potential reconnaissance efforts by an adversary to understand domain trust relationships, which can inform lateral movement strategies. If confirmed malicious, this could allow attackers to map out the network, identify potential targets, and plan further attacks, potentially compromising additional systems within the domain.

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
