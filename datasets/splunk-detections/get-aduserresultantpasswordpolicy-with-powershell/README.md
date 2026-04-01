# Get ADUserResultantPasswordPolicy with Powershell

**Type:** TTP

**Author:** Teoderick Contreras, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of `powershell.exe` running the `Get-ADUserResultantPasswordPolicy` cmdlet, which is used to obtain the password policy in a Windows domain. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as it indicates potential enumeration of domain policies, a common tactic for situational awareness and Active Directory discovery by adversaries. If confirmed malicious, this could allow attackers to understand password policies, aiding in further attacks such as password spraying or brute force attempts.

## MITRE ATT&CK

- T1201

## Analytic Stories

- Active Directory Discovery
- CISA AA23-347A

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1201/pwd_policy_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/get_aduserresultantpasswordpolicy_with_powershell.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
