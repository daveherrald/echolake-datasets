# Windows AD Short Lived Domain Controller SPN Attribute

**Type:** TTP

**Author:** Dean Luxton

## Description

The following analytic detects the temporary addition of a global catalog SPN or a DRS RPC SPN to an Active Directory computer object, indicative of a potential DCShadow attack. This detection leverages EventCode 5136 from the `wineventlog_security` data source, focusing on specific SPN attribute changes. This activity is significant as DCShadow attacks allow attackers with privileged access to register rogue Domain Controllers, enabling unauthorized changes to the AD infrastructure. If confirmed malicious, this could lead to unauthorized replication of changes, including credentials and keys, compromising the entire domain's security.

## MITRE ATT&CK

- T1207

## Analytic Stories

- Compromised Windows Host
- Sneaky Active Directory Persistence Tricks

## Data Sources

- Windows Event Log Security 5136
- Windows Event Log Security 4624

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1207/mimikatz/windows-security-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_short_lived_domain_controller_spn_attribute.yml)*
