# Windows Outlook WebView Registry Modification

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying modifications to specific Outlook registry values related to WebView and Today features. It detects when a URL is set in these registry locations, which could indicate attempts to manipulate Outlook's web-based components. The analytic focuses on changes to the "URL" value within Outlook's WebView and Today registry paths. This activity is significant as it may represent an attacker's effort to redirect Outlook's web content or inject malicious URLs. If successful, this technique could lead to phishing attempts, data theft, or serve as a stepping stone for further compromise of the user's email client and potentially sensitive information.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Suspicious Windows Registry Activities

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/atomic_red_team/windows-sysmon-webview.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_outlook_webview_registry_modification.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
