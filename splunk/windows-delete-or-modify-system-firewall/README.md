# Windows Delete or Modify System Firewall

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies 'netsh' processes that delete or modify firewall configurations. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions containing specific keywords. This activity is significant because it can indicate malware, such as NJRAT, attempting to alter firewall settings to evade detection or remove traces. If confirmed malicious, this behavior could allow an attacker to disable security measures, facilitating further compromise and persistence within the network.

## MITRE ATT&CK

- T1562.004

## Analytic Stories

- NjRAT
- ShrinkLocker

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.004/njrat_delete_firewall/njrat_delete_firewall.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_delete_or_modify_system_firewall.yml)*
