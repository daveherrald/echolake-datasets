# Windows AD Privileged Object Access Activity

**Type:** TTP

**Author:** Steven Dick

## Description

This dataset contains sample data for detecting access attempts to privileged Active Directory objects, such as Domain Admins or Enterprise Admins. It leverages Windows Security Event Code 4662 to identify when these sensitive objects are accessed. This activity is significant because such objects should rarely be accessed by normal users or processes, and unauthorized access attempts may indicate attacker enumeration or lateral movement within the domain. If confirmed malicious, this activity could allow attackers to escalate privileges, persist in the environment, or gain control over critical domain resources.

## MITRE ATT&CK

- T1087.002

## Analytic Stories

- Active Directory Discovery
- BlackSuit Ransomware

## Data Sources

- Windows Event Log Security 4662

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/4662_ad_enum/4662_priv_events.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_privileged_object_access_activity.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
