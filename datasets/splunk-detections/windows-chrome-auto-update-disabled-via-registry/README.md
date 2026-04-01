# Windows Chrome Auto-Update Disabled via Registry

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting modifications to Windows registry values that disable Google Chrome auto-updates.
Changes to values such as DisableAutoUpdateChecksCheckboxValue = 1, Update{8A69D345-D564-463C-AFF1-A69D9E530F96} = 0, UpdateDefault = 0, and AutoUpdateCheckPeriodMinutes = 0 can prevent Chrome from receiving security updates.
This behavior may indicate attempts to bypass update policies, maintain unauthorized extensions, or facilitate malware persistence.
Monitoring these registry changes helps identify potential policy violations or malicious activity targeting browser security.


## MITRE ATT&CK

- T1185

## Analytic Stories

- Browser Hijacking

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1185/disable_chrome_update/disable_chrome_update.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_chrome_auto_update_disabled_via_registry.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
