# Windows Event Logging Service Has Shutdown

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the shutdown of the Windows Event Log service by leveraging Windows Event ID 1100. This event is logged every time the service stops, including during normal system shutdowns. Monitoring this activity is crucial as it can indicate attempts to cover tracks or disable logging. If confirmed malicious, an attacker could hide their activities, making it difficult to trace their actions and investigate further incidents. Analysts should verify if the shutdown was planned and review other alerts and data sources for additional suspicious behavior.

## MITRE ATT&CK

- T1070.001

## Analytic Stories

- Windows Log Manipulation
- Ransomware
- Clop Ransomware
- Scattered Lapsus$ Hunters

## Data Sources

- Windows Event Log Security 1100

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.001/suspicious_event_log_service_behavior/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_event_logging_service_has_shutdown.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
