# Conti Common Exec parameter

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of suspicious command-line arguments commonly associated with Conti ransomware, specifically targeting local drives and network shares for encryption. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs that include command-line details. This activity is significant because it indicates a potential ransomware attack, which can lead to widespread data encryption and operational disruption. If confirmed malicious, the impact could be severe, resulting in data loss, system downtime, and potential ransom demands.

## MITRE ATT&CK

- T1204

## Analytic Stories

- Ransomware
- Compromised Windows Host
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/conti/inf1/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/conti_common_exec_parameter.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
