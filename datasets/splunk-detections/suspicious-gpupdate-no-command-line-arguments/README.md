# Suspicious GPUpdate no Command Line Arguments

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of gpupdate.exe without any command line arguments. This behavior is identified using data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs. It is significant because gpupdate.exe typically runs with specific arguments, and its execution without them is often associated with malicious activities, such as those performed by Cobalt Strike. If confirmed malicious, this activity could indicate an attempt to execute unauthorized commands or scripts, potentially leading to further system compromise or lateral movement within the network.

## MITRE ATT&CK

- T1055

## Analytic Stories

- BlackByte Ransomware
- Cobalt Strike
- Graceful Wipe Out Attack
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

*Source: [Splunk Security Content](detections/endpoint/suspicious_gpupdate_no_command_line_arguments.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
