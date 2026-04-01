# Windows PowerSploit GPP Discovery

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of the Get-GPPPassword PowerShell cmdlet, which is used to search for unsecured credentials in Group Policy Preferences (GPP). This detection leverages PowerShell Script Block Logging to identify specific script block text associated with this cmdlet. Monitoring this activity is crucial as it can indicate an attempt to retrieve and decrypt stored credentials from SYSVOL, potentially leading to unauthorized access. If confirmed malicious, this activity could allow an attacker to escalate privileges or move laterally within the network by exploiting exposed credentials.

## MITRE ATT&CK

- T1552.006

## Analytic Stories

- Active Directory Privilege Escalation

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552.006/powershell_gpp_discovery/win-powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powersploit_gpp_discovery.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
