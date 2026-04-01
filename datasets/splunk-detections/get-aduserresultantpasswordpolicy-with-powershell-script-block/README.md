# Get ADUserResultantPasswordPolicy with Powershell Script Block

**Type:** TTP

**Author:** Teoderick Contreras, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of the `Get-ADUserResultantPasswordPolicy` PowerShell cmdlet, which is used to obtain the password policy in a Windows domain. It leverages PowerShell Script Block Logging (EventCode=4104) to identify this activity. Monitoring this behavior is significant as it may indicate an attempt to enumerate domain policies, a common tactic used by adversaries for situational awareness and Active Directory discovery. If confirmed malicious, this activity could allow attackers to understand password policies, aiding in further attacks such as password guessing or policy exploitation.

## MITRE ATT&CK

- T1201

## Analytic Stories

- Active Directory Discovery
- CISA AA23-347A

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/sbl_xml.log


---

*Source: [Splunk Security Content](detections/endpoint/get_aduserresultantpasswordpolicy_with_powershell_script_block.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
