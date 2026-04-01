# Windows Modify Registry Disable Win Defender Raw Write Notif

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting modifications to the Windows registry that disable the Windows Defender raw write notification feature. It leverages data from the Endpoint.Registry datamodel, specifically monitoring changes to the registry path associated with Windows Defender's real-time protection settings. This activity is significant because disabling raw write notifications can allow malware, such as Azorult, to bypass Windows Defender's behavior monitoring, potentially leading to undetected malicious activities. If confirmed malicious, this could enable attackers to execute code, persist in the environment, and access sensitive information without detection.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Azorult
- CISA AA23-347A

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_disable_win_defender_raw_write_notif.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
