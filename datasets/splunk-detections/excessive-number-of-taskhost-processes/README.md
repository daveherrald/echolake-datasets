# Excessive number of taskhost processes

**Type:** Anomaly

**Author:** Michael Hart

## Description

This dataset contains sample data for identifying an excessive number of taskhost.exe and taskhostex.exe processes running within a short time frame. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and their counts. This behavior is significant as it is commonly associated with post-exploitation tools like Meterpreter and Koadic, which use multiple instances of these processes for actions such as discovery and lateral movement. If confirmed malicious, this activity could indicate an ongoing attack, allowing attackers to execute code, escalate privileges, or move laterally within the network.

## MITRE ATT&CK

- T1059

## Analytic Stories

- Meterpreter

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/excessive_distinct_processes_from_windows_temp/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/excessive_number_of_taskhost_processes.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
