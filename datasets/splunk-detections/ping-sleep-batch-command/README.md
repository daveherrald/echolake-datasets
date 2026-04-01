# Ping Sleep Batch Command

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying the execution of ping sleep batch commands.
It leverages data from Endpoint Detection and Response (EDR) agents, focusing on
process and parent process command-line details. This activity is significant as
it indicates an attempt to delay malicious code execution, potentially evading detection
or sandbox analysis. If confirmed malicious, this technique allows attackers to
bypass security measures, making it harder to detect and analyze their activities,
thereby increasing the risk of prolonged unauthorized access and potential data
exfiltration.


## MITRE ATT&CK

- T1497.003

## Analytic Stories

- Warzone RAT
- Quasar RAT
- Data Destruction
- Meduza Stealer
- WhisperGate
- BlackByte Ransomware

## Data Sources

- Sysmon EventID 1
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1497.003/ping_sleep/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/ping_sleep_batch_command.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
