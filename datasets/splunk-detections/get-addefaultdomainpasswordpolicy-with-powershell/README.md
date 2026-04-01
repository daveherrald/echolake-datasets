# Get ADDefaultDomainPasswordPolicy with Powershell

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of `powershell.exe` running the `Get-ADDefaultDomainPasswordPolicy` cmdlet, which is used to retrieve the password policy in a Windows domain. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. Monitoring this activity is crucial as it can indicate attempts by adversaries to gather information about domain policies for situational awareness and Active Directory discovery. If confirmed malicious, this activity could lead to further reconnaissance and potential exploitation of domain security settings.

## MITRE ATT&CK

- T1201

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1201/pwd_policy_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/get_addefaultdomainpasswordpolicy_with_powershell.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
