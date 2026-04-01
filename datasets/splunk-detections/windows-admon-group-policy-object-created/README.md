# Windows Admon Group Policy Object Created

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the creation of a new Group Policy Object (GPO) using Splunk's Admon data. It identifies events where a new GPO is created, excluding default "New Group Policy Object" entries. Monitoring GPO creation is crucial as adversaries can exploit GPOs to escalate privileges or deploy malware across an Active Directory network. If confirmed malicious, this activity could allow attackers to control system configurations, deploy ransomware, or propagate malware, significantly compromising the network's security.

## MITRE ATT&CK

- T1484.001

## Analytic Stories

- Active Directory Privilege Escalation
- Sneaky Active Directory Persistence Tricks

## Data Sources

- Windows Active Directory Admon

## Sample Data

- **Source:** ActiveDirectory
  **Sourcetype:** ActiveDirectory
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1484.001/group_policy_created/windows-admon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_admon_group_policy_object_created.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
