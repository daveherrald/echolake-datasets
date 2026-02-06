# Windows Create Local Account

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the creation of a new local user account on a Windows system. It leverages Windows Security Audit logs, specifically event ID 4720, to identify this activity. Monitoring the creation of local accounts is crucial for a SOC as it can indicate unauthorized access or lateral movement within the network. If confirmed malicious, this activity could allow an attacker to establish persistence, escalate privileges, or gain unauthorized access to sensitive systems and data.

## MITRE ATT&CK

- T1136.001

## Analytic Stories

- Active Directory Password Spraying
- CISA AA24-241A
- GhostRedirector IIS Module and Rungan Backdoor
- Scattered Lapsus$ Hunters

## Data Sources

- Windows Event Log Security 4720

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/4720.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_create_local_account.yml)*
