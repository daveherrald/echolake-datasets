# User Discovery With Env Vars PowerShell

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of `powershell.exe` with command-line arguments that use PowerShell environment variables to identify the current logged user. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as adversaries may use it for situational awareness and Active Directory discovery on compromised endpoints. If confirmed malicious, this behavior could allow attackers to gather critical user information, aiding in further exploitation and lateral movement within the network.

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

*Source: [Splunk Security Content](detections/endpoint/user_discovery_with_env_vars_powershell.yml)*
