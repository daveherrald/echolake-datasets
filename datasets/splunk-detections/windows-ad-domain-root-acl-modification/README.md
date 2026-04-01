# Windows AD Domain Root ACL Modification

**Type:** TTP

**Author:** Dean Luxton

## Description

ACL modification performed on the domain root object, significant AD change with high impact. Following MS guidance all changes at this level should be reviewed. Drill into the logonID within EventCode 4624 for information on the source device during triage.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1222.001/dacl_abuse/domain_root_acl_mod_windows-security-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_domain_root_acl_modification.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
