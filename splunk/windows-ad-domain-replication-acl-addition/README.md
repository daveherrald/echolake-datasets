# Windows AD Domain Replication ACL Addition

**Type:** TTP

**Author:** Dean Luxton

## Description

The following analytic detects the addition of permissions required for a DCSync attack, specifically DS-Replication-Get-Changes, DS-Replication-Get-Changes-All, and DS-Replication-Get-Changes-In-Filtered-Set. It leverages EventCode 5136 from the Windows Security Event Log to identify when these permissions are granted. This activity is significant because it indicates potential preparation for a DCSync attack, which can be used to replicate AD objects and exfiltrate sensitive data. If confirmed malicious, an attacker could gain extensive access to Active Directory, leading to severe data breaches and privilege escalation.

## MITRE ATT&CK

- T1484

## Analytic Stories

- Compromised Windows Host
- Sneaky Active Directory Persistence Tricks

## Data Sources

- Windows Event Log Security 5136

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1484/aclmodification/windows-security-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_domain_replication_acl_addition.yml)*
