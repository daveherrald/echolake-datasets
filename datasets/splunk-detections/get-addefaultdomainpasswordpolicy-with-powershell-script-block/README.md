# Get ADDefaultDomainPasswordPolicy with Powershell Script Block

**Type:** Hunting

**Author:** Teoderick Contreras, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of the `Get-ADDefaultDomainPasswordPolicy` PowerShell cmdlet, which is used to retrieve the password policy in a Windows domain. This detection leverages PowerShell Script Block Logging (EventCode=4104) to identify the specific command execution. Monitoring this activity is significant as it can indicate an attempt to gather domain policy information, which is often a precursor to further malicious actions. If confirmed malicious, this activity could allow an attacker to understand password policies, aiding in password attacks or further domain enumeration.

## MITRE ATT&CK

- T1201

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1201/pwd_policy_discovery/windows-powershell-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/get_addefaultdomainpasswordpolicy_with_powershell_script_block.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
