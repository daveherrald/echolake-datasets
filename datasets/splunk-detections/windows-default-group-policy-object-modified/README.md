# Windows Default Group Policy Object Modified

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting modifications to default Group Policy Objects (GPOs) using Event ID 5136. It monitors changes to the `Default Domain Controllers Policy` and `Default Domain Policy`, which are critical for enforcing security settings across domain controllers and all users/computers, respectively. This activity is significant because unauthorized changes to these GPOs can indicate an adversary with privileged access attempting to deploy persistence mechanisms or execute malware across the network. If confirmed malicious, such modifications could lead to widespread compromise, allowing attackers to maintain control and execute arbitrary code on numerous hosts.

## MITRE ATT&CK

- T1484.001

## Analytic Stories

- Active Directory Privilege Escalation
- Sneaky Active Directory Persistence Tricks

## Data Sources

- Windows Event Log Security 5136

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1484.001/default_domain_policy_modified/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_default_group_policy_object_modified.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
