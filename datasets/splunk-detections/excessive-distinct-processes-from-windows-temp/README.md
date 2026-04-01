# Excessive distinct processes from Windows Temp

**Type:** Anomaly

**Author:** Michael Hart, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying an excessive number of distinct processes executing from the Windows\Temp directory. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process paths and counts within a 20-minute window. This behavior is significant as it often indicates the presence of post-exploit frameworks like Koadic and Meterpreter, which use this technique to execute malicious actions. If confirmed malicious, this activity could allow attackers to execute arbitrary code, escalate privileges, and maintain persistence within the environment, posing a severe threat to system integrity and security.

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

*Source: [Splunk Security Content](detections/endpoint/excessive_distinct_processes_from_windows_temp.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
