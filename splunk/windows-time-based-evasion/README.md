# Windows Time Based Evasion

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects potentially malicious processes that initiate a ping delay using an invalid IP address. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions involving "ping 0 -n". This behavior is significant as it is commonly used by malware like NJRAT to introduce time delays for evasion tactics, such as delaying self-deletion. If confirmed malicious, this activity could indicate an active infection attempting to evade detection, potentially leading to further compromise and persistence within the environment.

## MITRE ATT&CK

- T1497.003

## Analytic Stories

- NjRAT

## Data Sources

- Sysmon EventID 1
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1497.003/njrat_ping_delay_before_delete/ping_0.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_time_based_evasion.yml)*
