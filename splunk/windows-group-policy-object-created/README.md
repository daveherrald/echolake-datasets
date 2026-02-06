# Windows Group Policy Object Created

**Type:** TTP

**Author:** Mauricio Velazco

## Description

The following analytic detects the creation of a new Group Policy Object (GPO) by leveraging Event IDs 5136 and 5137. This detection uses directory service change events to identify when a new GPO is created. Monitoring GPO creation is crucial as adversaries can exploit GPOs to escalate privileges or deploy malware across an Active Directory network. If confirmed malicious, this activity could allow attackers to control system configurations, deploy ransomware, or propagate malware, leading to widespread compromise and significant operational disruption.

## MITRE ATT&CK

- T1078.002
- T1484.001

## Analytic Stories

- Active Directory Privilege Escalation
- Sneaky Active Directory Persistence Tricks

## Data Sources

- Windows Event Log Security 5136
- Windows Event Log Security 5137

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1484.001/group_policy_created/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_group_policy_object_created.yml)*
