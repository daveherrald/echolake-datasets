# Windows KrbRelayUp Service Creation

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the creation of a service with the default name "KrbSCM" associated with the KrbRelayUp tool. It leverages Windows System Event Logs, specifically EventCode 7045, to identify this activity. This behavior is significant as KrbRelayUp is a known tool used for privilege escalation attacks. If confirmed malicious, this activity could allow an attacker to escalate privileges, potentially gaining unauthorized access to sensitive systems and data.

## MITRE ATT&CK

- T1543.003

## Analytic Stories

- Local Privilege Escalation With KrbRelayUp
- Compromised Windows Host

## Data Sources

- Windows Event Log System 7045

## Sample Data

- **Source:** XmlWinEventLog:System
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1543.003/windows_krbrelayup_service_creation/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_krbrelayup_service_creation.yml)*
