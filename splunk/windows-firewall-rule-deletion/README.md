# Windows Firewall Rule Deletion

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This detection identifies instances where a Windows Firewall rule has been deleted, potentially exposing the system to security risks. Unauthorized removal of firewall rules can indicate an attacker attempting to bypass security controls or malware disabling protections for persistence and command-and-control communication. The event logs details such as the deleted rule name, protocol, port, and the user responsible for the action. Security teams should monitor for unexpected deletions, correlate with related events, and investigate anomalies to prevent unauthorized access and maintain network security posture.

## MITRE ATT&CK

- T1562.004

## Analytic Stories

- ShrinkLocker
- Medusa Ransomware
- NetSupport RMM Tool Abuse

## Data Sources

- Windows Event Log Security 4948

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.004/firewall_win_event/delete_rule/MPSSVC_Rule-Level_Policy_Change-4948.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_firewall_rule_deletion.yml)*
