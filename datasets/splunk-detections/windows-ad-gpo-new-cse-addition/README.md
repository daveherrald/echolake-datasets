# Windows AD GPO New CSE Addition

**Type:** TTP

**Author:** Dean Luxton

## Description

This detection identifies when a a new client side extension is added to an Active Directory Group Policy using the Group Policy Management Console.

## MITRE ATT&CK

- T1222.001
- T1484.001

## Analytic Stories

- Sneaky Active Directory Persistence Tricks

## Data Sources

- Windows Event Log Security 5136

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1484.001/group_policy_new_cse/windows-security.log

- **Source:** ActiveDirectory
  **Sourcetype:** ActiveDirectory
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1484.001/group_policy_new_cse/windows-admon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_gpo_new_cse_addition.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
