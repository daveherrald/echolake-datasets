# Windows AD Privileged Account SID History Addition

**Type:** TTP

**Author:** Dean Luxton

## Description

The following analytic identifies when the SID of a privileged user is added to the SID History attribute of another user. It leverages Windows Security Event Codes 4742 and 4738, combined with identity lookups, to detect this activity. This behavior is significant as it may indicate an attempt to abuse SID history for unauthorized access across multiple domains. If confirmed malicious, this activity could allow an attacker to escalate privileges or maintain persistent access within the environment, posing a significant security risk.

## MITRE ATT&CK

- T1134.005

## Analytic Stories

- Compromised Windows Host
- Sneaky Active Directory Persistence Tricks

## Data Sources

- Windows Event Log Security 4742
- Windows Event Log Security 4738

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1134.005/mimikatz/windows-security-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ad_privileged_account_sid_history_addition.yml)*
