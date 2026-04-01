# Windows Modify Registry Delete Firewall Rules

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a potential deletion of firewall rules, indicating a possible security breach or unauthorized access attempt. It identifies actions where firewall rules are removed using commands like netsh advfirewall firewall delete rule, which can expose the network to external threats by disabling critical security measures. Monitoring these activities helps maintain network integrity and prevent malicious attacks.

## MITRE ATT&CK

- T1112

## Analytic Stories

- ShrinkLocker
- CISA AA24-241A
- NetSupport RMM Tool Abuse

## Data Sources

- Sysmon EventID 12

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/firewall_modify_delete/firewall_mod_delete.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_delete_firewall_rules.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
