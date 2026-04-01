# Windows Find Interesting ACL with FindInterestingDomainAcl

**Type:** TTP

**Author:** Gowthamaraj Rajendran, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of the `Find-InterestingDomainAcl` cmdlet, part of the PowerView toolkit, using PowerShell Script Block Logging (EventCode=4104). This detection leverages logs to identify when this command is run, which is significant as adversaries may use it to find misconfigured or unusual Access Control Lists (ACLs) within a domain. If confirmed malicious, this activity could allow attackers to identify privilege escalation opportunities or weak security configurations in Active Directory, potentially leading to unauthorized access or further exploitation.

## MITRE ATT&CK

- T1087.002

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/AD_discovery/windows-powershell-interestingACL-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_find_interesting_acl_with_findinterestingdomainacl.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
