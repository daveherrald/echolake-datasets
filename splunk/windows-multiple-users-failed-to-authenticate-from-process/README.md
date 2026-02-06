# Windows Multiple Users Failed To Authenticate From Process

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects a source process failing to authenticate with 30 unique users, indicating a potential Password Spraying attack. It leverages Windows Event 4625 with Logon Type 2, collected from domain controllers, member servers, and workstations. This activity is significant as it may represent an adversary attempting to gain initial access or elevate privileges within an Active Directory environment. If confirmed malicious, this could lead to unauthorized access, privilege escalation, or further compromise of the network, posing a severe security risk.

## MITRE ATT&CK

- T1110.003

## Analytic Stories

- Active Directory Password Spraying
- Insider Threat
- Volt Typhoon

## Data Sources

- Windows Event Log Security 4625

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/purplesharp_multiple_users_from_process_xml/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_multiple_users_failed_to_authenticate_from_process.yml)*
