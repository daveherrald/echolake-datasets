# Windows Information Discovery Fsutil

**Type:** Anomaly

**Author:** Teoderick Contreras, Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for identifying the execution of the Windows built-in tool FSUTIL with the "FSINFO" or "Volume" parameters, in order to discover file system and disk information.
This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs that include command-line details.
Monitoring this activity is significant because FSUTIL can be abused by adversaries to gather detailed information about the file system, aiding in further exploitation.
If confirmed malicious, this activity could enable attackers to map the file system, identify valuable data, and plan subsequent actions such as privilege escalation or persistence.


## MITRE ATT&CK

- T1082

## Analytic Stories

- Windows Post-Exploitation
- Prestige Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/winpeas/winpeas_fsutil/fsutil-fsinfo-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_information_discovery_fsutil.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
