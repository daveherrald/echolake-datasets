# Windows AD Abnormal Object Access Activity

**Type:** Anomaly

**Author:** Steven Dick

## Description

The following analytic identifies a statistically significant increase in access to Active Directory objects, which may indicate attacker enumeration. It leverages Windows Security Event Code 4662 to monitor and analyze access patterns, comparing them against historical averages to detect anomalies. This activity is significant for a SOC because abnormal access to AD objects can be an early indicator of reconnaissance efforts by an attacker. If confirmed malicious, this behavior could lead to unauthorized access, privilege escalation, or further compromise of the Active Directory environment.

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

*Source: [Splunk Security Content](detections/endpoint/windows_ad_abnormal_object_access_activity.yml)*
