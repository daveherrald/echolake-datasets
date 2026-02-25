# Windows Default Group Policy Object Modified with GPME

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting modifications to default Group Policy Objects (GPOs) using the Group Policy Management Editor (GPME). It leverages the Endpoint data model to identify processes where `mmc.exe` executes `gpme.msc` with specific GUIDs related to default GPOs. This activity is significant because default GPOs, such as the `Default Domain Controllers Policy` and `Default Domain Policy`, are critical for enforcing security policies across the domain. If malicious, such modifications could allow an attacker to gain further access, establish persistence, or deploy malware across numerous hosts, severely compromising the network's security.

## MITRE ATT&CK

- T1484.001

## Analytic Stories

- Active Directory Privilege Escalation
- Sneaky Active Directory Persistence Tricks

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1484.001/default_domain_policy_modified/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_default_group_policy_object_modified_with_gpme.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
