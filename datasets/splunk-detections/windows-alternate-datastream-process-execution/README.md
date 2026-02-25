# Windows Alternate DataStream - Process Execution

**Type:** TTP

**Author:** Steven Dick

## Description

This dataset contains sample data for detecting when a process attempts to execute a file from within an NTFS file system alternate data stream. This detection leverages process execution data from sources like Windows process monitoring or Sysmon Event ID 1, focusing on specific processes known for such behavior. This activity is significant because alternate data streams can be used by threat actors to hide malicious code, making it difficult to detect. If confirmed malicious, this could allow an attacker to execute hidden code, potentially leading to unauthorized actions and further compromise of the system.

## MITRE ATT&CK

- T1564.004

## Analytic Stories

- Compromised Windows Host
- Windows Defense Evasion Tactics

## Data Sources

- Windows Event Log Security 4688
- Sysmon EventID 1

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1564.004/ads_abuse/ads_abuse_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_alternate_datastream___process_execution.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
