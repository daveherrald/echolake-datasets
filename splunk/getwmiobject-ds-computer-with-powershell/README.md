# GetWmiObject Ds Computer with PowerShell

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of `powershell.exe` with command-line arguments that utilize the `Get-WmiObject` cmdlet to discover remote systems, specifically targeting the `DS_Computer` parameter. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as it indicates potential reconnaissance efforts by adversaries to enumerate domain computers and gather situational awareness within Active Directory. If confirmed malicious, this behavior could allow attackers to map the network, identify critical systems, and plan further attacks, potentially leading to unauthorized access and data exfiltration.

## MITRE ATT&CK

- T1018

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1018/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/getwmiobject_ds_computer_with_powershell.yml)*
