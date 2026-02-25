# Windows Application Layer Protocol RMS Radmin Tool Namedpipe

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the use of default or publicly known named pipes associated with the RMX remote admin tool. It leverages Sysmon EventCodes 17 and 18 to identify named pipe creation and connection events. This activity is significant as the RMX tool has been abused by adversaries and malware like Azorult to collect data from targeted hosts. If confirmed malicious, this could indicate unauthorized remote administration capabilities, leading to data exfiltration or further compromise of the affected system. Immediate investigation is required to determine the legitimacy of this tool's presence.

## MITRE ATT&CK

- T1071

## Analytic Stories

- Azorult

## Data Sources

- Sysmon EventID 17
- Sysmon EventID 18

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_application_layer_protocol_rms_radmin_tool_namedpipe.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
