# Windows AD Domain Controller Promotion

**Type:** TTP

**Author:** Dean Luxton

## Description

The following analytic identifies a genuine Domain Controller (DC) promotion event by detecting when a computer assigns itself the necessary Service Principal Names (SPNs) to function as a domain controller. It leverages Windows Security Event Code 4742 to monitor existing domain controllers for these changes. This activity is significant as it can help identify rogue DCs added to the network, which could indicate a DCShadow attack. If confirmed malicious, this could allow an attacker to manipulate Active Directory, leading to potential privilege escalation and persistent access within the environment.

## MITRE ATT&CK

- T1207

## Analytic Stories

- Compromised Windows Host
- Sneaky Active Directory Persistence Tricks

## Data Sources

- Windows Event Log Security 4742

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1207/dc_promo/windows-security-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_domain_controller_promotion.yml)*
