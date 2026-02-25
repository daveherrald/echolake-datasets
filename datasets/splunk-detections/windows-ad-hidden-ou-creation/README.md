# Windows AD Hidden OU Creation

**Type:** TTP

**Author:** Dean Luxton

## Description

This analytic is looking for when an ACL is applied to an OU which denies listing the objects residing in the OU. This activity combined with modifying the owner of the OU will hide AD objects even from domain administrators.

## MITRE ATT&CK

- T1222.001
- T1484

## Analytic Stories

- Sneaky Active Directory Persistence Tricks

## Data Sources

- Windows Event Log Security 5136

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1222.001/dacl_abuse/hidden_ou_windows-security-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_hidden_ou_creation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
