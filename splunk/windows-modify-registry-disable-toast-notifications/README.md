# Windows Modify Registry Disable Toast Notifications

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications to the Windows registry that disable toast notifications. It leverages data from the Endpoint.Registry datamodel, specifically monitoring changes to the registry path "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\\ToastEnabled*" with a value set to "0x00000000". This activity is significant because disabling toast notifications can prevent users from receiving critical system and application updates, which adversaries like Azorult exploit for defense evasion. If confirmed malicious, this action could allow attackers to operate undetected, leading to prolonged persistence and potential further compromise of the system.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Azorult

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_disable_toast_notifications.yml)*
