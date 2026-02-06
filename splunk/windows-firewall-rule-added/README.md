# Windows Firewall Rule Added

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This detection identifies instances where a Windows Firewall rule is added by monitoring Event ID 4946 in the Windows Security Event Log. Firewall rule modifications can indicate legitimate administrative actions, but they may also signal unauthorized changes, misconfigurations, or malicious activity such as attackers allowing traffic for backdoors or persistence mechanisms. By analyzing fields like RuleName, RuleId, Computer, and ProfileChanged, security teams can determine whether the change aligns with expected behavior. Correlating with user activity and process execution can help distinguish false positives from real threats, ensuring better visibility into potential security risks.

## MITRE ATT&CK

- T1562.004

## Analytic Stories

- ShrinkLocker
- Medusa Ransomware
- NetSupport RMM Tool Abuse

## Data Sources

- Windows Event Log Security 4946

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.004/firewall_win_event/added_rule/MPSSVC_Rule-Level_Policy_Change-4946.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_firewall_rule_added.yml)*
