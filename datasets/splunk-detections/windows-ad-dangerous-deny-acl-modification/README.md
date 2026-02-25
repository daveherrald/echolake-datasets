# Windows AD Dangerous Deny ACL Modification

**Type:** TTP

**Author:** Dean Luxton

## Description

This detection identifies an Active Directory access-control list (ACL) modification event, which applies permissions that deny the ability to enumerate permissions of the object.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1222.001/dacl_abuse/hidden_object_windows-security-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_dangerous_deny_acl_modification.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
