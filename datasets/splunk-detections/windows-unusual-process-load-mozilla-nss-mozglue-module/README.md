# Windows Unusual Process Load Mozilla NSS-Mozglue Module

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying processes loading Mozilla NSS-Mozglue libraries such as mozglue.dll and nss3.dll. It leverages Sysmon Event logs, specifically monitoring EventCode 7, which tracks image loaded events. This activity is significant because it can indicate unauthorized access or manipulation of these libraries, which are commonly used by Mozilla applications like Firefox and Thunderbird. If confirmed malicious, this could lead to data exfiltration, credential theft, or further compromise of the system.

## MITRE ATT&CK

- T1218.003

## Analytic Stories

- StealC Stealer
- Quasar RAT
- 0bj3ctivity Stealer
- Lokibot

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.003/moz_lib_loaded/mozilla_lib.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_unusual_process_load_mozilla_nss_mozglue_module.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
