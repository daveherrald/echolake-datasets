# Windows Process With NamedPipe CommandLine

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting processes with command lines containing named pipes. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process command-line executions. This behavior is significant as it is often used by adversaries, such as those behind the Olympic Destroyer malware, for inter-process communication post-injection, aiding in defense evasion and privilege escalation. If confirmed malicious, this activity could allow attackers to maintain persistence, escalate privileges, or evade defenses, potentially leading to further compromise of the system.

## MITRE ATT&CK

- T1055

## Analytic Stories

- Windows Defense Evasion Tactics

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/olympic_destroyer/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_process_with_namedpipe_commandline.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
