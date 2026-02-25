# GetWmiObject User Account with PowerShell

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of `powershell.exe` with command-line arguments that utilize the `Get-WmiObject` cmdlet and the `Win32_UserAccount` parameter to query local user accounts. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as it may indicate an attempt by adversaries to enumerate user accounts for situational awareness or Active Directory discovery. If confirmed malicious, this behavior could lead to further reconnaissance, privilege escalation, or lateral movement within the network.

## MITRE ATT&CK

- T1087.001

## Analytic Stories

- Winter Vivern
- Active Directory Discovery
- Water Gamayun

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.001/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/getwmiobject_user_account_with_powershell.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
