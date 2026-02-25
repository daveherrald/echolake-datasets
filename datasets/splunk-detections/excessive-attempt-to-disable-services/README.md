# Excessive Attempt To Disable Services

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying a suspicious series of command-line executions attempting to disable multiple services. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on processes where "sc.exe" is used with parameters like "config" or "Disabled" within a short time frame. This activity is significant as it may indicate an adversary's attempt to disable security or other critical services to further compromise the system. If confirmed malicious, this could lead to the attacker achieving persistence, evading detection, or disabling security mechanisms, thereby increasing the risk of further exploitation.

## MITRE ATT&CK

- T1489

## Analytic Stories

- XMRig
- Azorult

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/excessive_attempt_to_disable_services.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
