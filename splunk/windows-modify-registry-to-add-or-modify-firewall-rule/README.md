# Windows Modify Registry to Add or Modify Firewall Rule

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects a potential addition or modification of firewall rules, signaling possible configuration changes or security policy adjustments. It tracks commands such as netsh advfirewall firewall add rule and netsh advfirewall firewall set rule, which may indicate attempts to alter network access controls. Monitoring these actions ensures the integrity of firewall settings and helps prevent unauthorized network access.

## MITRE ATT&CK

- T1112

## Analytic Stories

- ShrinkLocker
- CISA AA24-241A
- NetSupport RMM Tool Abuse

## Data Sources

- Sysmon EventID 13
- Sysmon EventID 14

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/firewall_modify_delete/firewall_mod_delete.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_to_add_or_modify_firewall_rule.yml)*
