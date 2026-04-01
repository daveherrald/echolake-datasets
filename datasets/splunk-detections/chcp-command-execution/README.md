# CHCP Command Execution

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of the chcp.com utility, which is used to change the active code page of the console. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events. This activity is significant because it can indicate the presence of malware, such as IcedID, which uses this technique to determine the locale region, language, or country of the compromised host. If confirmed malicious, this could lead to further system compromise and data exfiltration.

## MITRE ATT&CK

- T1059

## Analytic Stories

- IcedID
- Azorult
- Crypto Stealer
- Quasar RAT
- Forest Blizzard
- Interlock Rat

## Data Sources

- Sysmon EventID 1
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/simulated_icedid/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/chcp_command_execution.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
