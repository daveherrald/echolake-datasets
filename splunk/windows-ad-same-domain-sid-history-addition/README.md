# Windows AD Same Domain SID History Addition

**Type:** TTP

**Author:** Dean Luxton

## Description

The following analytic detects changes to the sIDHistory attribute of user or computer objects within the same domain. It leverages Windows Security Event Codes 4738 and 4742 to identify when the sIDHistory attribute is modified. This activity is significant because the sIDHistory attribute can be abused by adversaries to grant unauthorized access by inheriting permissions from another account. If confirmed malicious, this could allow attackers to maintain persistent access or escalate privileges within the domain, posing a severe security risk.

## MITRE ATT&CK

- T1134.005

## Analytic Stories

- Compromised Windows Host
- Windows Persistence Techniques
- Sneaky Active Directory Persistence Tricks

## Data Sources

- Windows Event Log Security 4742
- Windows Event Log Security 4738

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1134.005/mimikatz/windows-security-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_same_domain_sid_history_addition.yml)*
