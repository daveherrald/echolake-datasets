# GetLocalUser with PowerShell

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of `powershell.exe` with the `Get-LocalUser` commandlet, which is used to query local user accounts. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. Monitoring this activity is significant because adversaries and Red Teams may use it to enumerate local users for situational awareness and Active Directory discovery. If confirmed malicious, this activity could allow attackers to identify potential targets for further exploitation or privilege escalation within the environment.

## MITRE ATT&CK

- T1087.001

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.001/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/getlocaluser_with_powershell.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
