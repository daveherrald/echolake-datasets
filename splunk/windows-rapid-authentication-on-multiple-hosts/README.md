# Windows Rapid Authentication On Multiple Hosts

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects a source computer authenticating to 30 or more remote endpoints within a 5-minute timespan using Event ID 4624. This behavior is identified by analyzing Windows Event Logs for LogonType 3 events and counting unique target computers. Such activity is significant as it may indicate lateral movement or network share enumeration by an adversary. If confirmed malicious, this could lead to unauthorized access to multiple systems, potentially compromising sensitive data and escalating privileges within the network.

## MITRE ATT&CK

- T1003.002

## Analytic Stories

- Active Directory Privilege Escalation
- Active Directory Lateral Movement

## Data Sources

- Windows Event Log Security 4624

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1135/rapid_authentication_multiple_hosts/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_rapid_authentication_on_multiple_hosts.yml)*
