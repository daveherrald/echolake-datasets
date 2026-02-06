# Windows Disable Shutdown Button Through Registry

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic detects suspicious registry modifications that disable the shutdown button on a user's logon screen. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to registry paths associated with shutdown policies. This activity is significant because it is a tactic used by malware, particularly ransomware like KillDisk, to hinder system usability and prevent the removal of malicious changes. If confirmed malicious, this could impede system recovery efforts, making it difficult to restart the machine and remove other harmful modifications.

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
