# Suspicious SearchProtocolHost no Command Line Arguments

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting instances of searchprotocolhost.exe running without command line arguments. This behavior is unusual and often associated with malicious activities, such as those performed by Cobalt Strike. The detection leverages Endpoint Detection and Response (EDR) telemetry, focusing on process execution data. This activity is significant because searchprotocolhost.exe typically runs with specific arguments, and its absence may indicate an attempt to evade detection. If confirmed malicious, this could lead to unauthorized code execution, potential credential dumping, or other malicious actions within the environment.

## MITRE ATT&CK

- T1055

## Analytic Stories

- BlackByte Ransomware
- Cobalt Strike
- Graceful Wipe Out Attack
- Cactus Ransomware
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_searchprotocolhost_no_command_line_arguments.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
