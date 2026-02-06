# Get-ForestTrust with PowerShell

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of the Get-ForestTrust command via PowerShell, commonly used by adversaries to gather domain trust information. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. Identifying this activity is crucial as it indicates potential reconnaissance efforts to map out domain trusts, which can inform further attacks. If confirmed malicious, this activity could allow attackers to understand domain relationships, aiding in lateral movement and privilege escalation within the network.

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

*Source: [Splunk Security Content](detections/endpoint/get_foresttrust_with_powershell.yml)*
