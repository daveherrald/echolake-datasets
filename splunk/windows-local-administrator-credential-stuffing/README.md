# Windows Local Administrator Credential Stuffing

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects attempts to authenticate using the built-in local Administrator account across more than 30 endpoints within a 5-minute window. It leverages Windows Event Logs, specifically events 4625 and 4624, to identify this behavior. This activity is significant as it may indicate an adversary attempting to validate stolen local credentials across multiple hosts, potentially leading to privilege escalation. If confirmed malicious, this could allow the attacker to gain widespread access and control over numerous systems within the network, posing a severe security risk.

## MITRE ATT&CK

- T1110.004

## Analytic Stories

- Active Directory Privilege Escalation
- Active Directory Lateral Movement
- Scattered Lapsus$ Hunters

## Data Sources

- Windows Event Log Security 4624
- Windows Event Log Security 4625

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.004/local_administrator_cred_stuffing/windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_local_administrator_credential_stuffing.yml)*
