# Detect RTLO In Process

**Type:** TTP

**Author:** Steven Dick

## Description

This dataset contains sample data for identifying the abuse of the right-to-left override (RTLO) character (U+202E) in process names. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs and command-line data. This activity is significant because adversaries use the RTLO character to disguise malicious files or commands, making them appear benign. If confirmed malicious, this technique can allow attackers to execute harmful code undetected, potentially leading to unauthorized access, data exfiltration, or further system compromise.

## MITRE ATT&CK

- T1036.002

## Analytic Stories

- Spearphishing Attachments

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036.002/outlook_attachment/rtlo_events.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_rtlo_in_process.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
