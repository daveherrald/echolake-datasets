# Revil Common Exec Parameter

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of command-line parameters commonly associated with REVIL ransomware, such as "-nolan", "-nolocal", "-fast", and "-full". It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs mapped to the `Processes` node of the `Endpoint` data model. This activity is significant because these parameters are indicative of ransomware attempting to encrypt files on a compromised machine. If confirmed malicious, this could lead to widespread data encryption, rendering critical files inaccessible and potentially causing significant operational disruption.

## MITRE ATT&CK

- T1204

## Analytic Stories

- Ransomware
- Revil Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/revil/inf1/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/revil_common_exec_parameter.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
