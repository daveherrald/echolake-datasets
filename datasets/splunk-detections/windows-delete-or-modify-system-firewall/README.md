# Windows Delete or Modify System Firewall

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying 'netsh' processes that delete or modify firewall configurations. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions containing specific keywords. This activity is significant because it can indicate malware, such as NJRAT, attempting to alter firewall settings to evade detection or remove traces. If confirmed malicious, this behavior could allow an attacker to disable security measures, facilitating further compromise and persistence within the network.

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


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
