# Windows AD AdminSDHolder ACL Modified

**Type:** TTP

**Author:** Mauricio Velazco, Dean Luxton, Splunk

## Description

The following analytic detects modifications to the Access Control List (ACL) of the AdminSDHolder object in a Windows domain, specifically the addition of new rules. It leverages EventCode 5136 from the Security Event Log, focusing on changes to the nTSecurityDescriptor attribute. This activity is significant because the AdminSDHolder object secures privileged group members, and unauthorized changes can allow attackers to establish persistence and escalate privileges. If confirmed malicious, this could enable an attacker to control domain-level permissions, compromising the entire Active Directory environment.

## MITRE ATT&CK

- T1546

## Analytic Stories

- Sneaky Active Directory Persistence Tricks

## Data Sources

- Windows Event Log Security 5136

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546/adminsdholder_modified/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_adminsdholder_acl_modified.yml)*
