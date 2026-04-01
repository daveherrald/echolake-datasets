# Windows AD Suspicious Attribute Modification

**Type:** TTP

**Author:** Dean Luxton

## Description

This detection monitors changes to the following Active Directory attributes: "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-KeyCredentialLink", "scriptPath", and "msTSInitialProgram".  Modifications to these attributes can indicate potential malicious activity or privilege escalation attempts. Immediate investigation is recommended upon alert.

## MITRE ATT&CK

- T1222.001
- T1550

## Analytic Stories

- Sneaky Active Directory Persistence Tricks

## Data Sources

- Windows Event Log Security 5136

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1222.001/dacl_abuse/suspicious_acl_modification-windows-security-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_suspicious_attribute_modification.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
