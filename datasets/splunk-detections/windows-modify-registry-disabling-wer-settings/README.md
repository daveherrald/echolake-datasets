# Windows Modify Registry Disabling WER Settings

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting modifications in the Windows registry to disable Windows Error Reporting (WER) settings. It leverages data from the Endpoint.Registry datamodel, specifically monitoring changes to registry paths related to WER with a value set to "0x00000001". This activity is significant as adversaries may disable WER to suppress error notifications, hiding the presence of malicious activities. If confirmed malicious, this could allow attackers to operate undetected, potentially leading to prolonged persistence and further exploitation within the environment.

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

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_disabling_wer_settings.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
