# Windows Chrome Extension Allowed Registry Modification

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting modifications to the Windows registry keys that control the Chrome Extension Install Allowlist. Unauthorized changes to these keys may indicate attempts to bypass Chrome extension restrictions or install unapproved extensions. This detection helps identify potential security policy violations or malicious activity targeting Chrome extension settings.

## MITRE ATT&CK

- T1185

## Analytic Stories

- Browser Hijacking

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1185/chrome_allow_list/chrome_extension_allow_list.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_chrome_extension_allowed_registry_modification.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
