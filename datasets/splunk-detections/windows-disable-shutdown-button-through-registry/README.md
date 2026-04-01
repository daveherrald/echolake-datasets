# Windows Disable Shutdown Button Through Registry

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

This dataset contains sample data for detecting suspicious registry modifications that disable the shutdown button on a user's logon screen. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to registry paths associated with shutdown policies. This activity is significant because it is a tactic used by malware, particularly ransomware like KillDisk, to hinder system usability and prevent the removal of malicious changes. If confirmed malicious, this could impede system recovery efforts, making it difficult to restart the machine and remove other harmful modifications.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Ransomware
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/ransomware_disable_reg/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_disable_shutdown_button_through_registry.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
