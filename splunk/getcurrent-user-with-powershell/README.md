# GetCurrent User with PowerShell

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of `powershell.exe` with command-line arguments invoking the `GetCurrent` method of the WindowsIdentity .NET class. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as adversaries may use this method to identify the logged-in user on a compromised endpoint, aiding in situational awareness and Active Directory discovery. If confirmed malicious, this could allow attackers to gain insights into user context, potentially facilitating further exploitation and lateral movement within the network.

## MITRE ATT&CK

- T1033

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1033/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/getcurrent_user_with_powershell.yml)*
