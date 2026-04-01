# Windows Query Registry Browser List Application

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a suspicious process accessing the registry entries for default internet browsers. It leverages Windows Security Event logs, specifically event code 4663, to identify access attempts to these registry paths. This activity is significant because adversaries can exploit this registry key to gather information about installed browsers and their settings, potentially leading to the theft of sensitive data such as login credentials and browsing history. If confirmed malicious, this behavior could enable attackers to exfiltrate sensitive information and compromise user accounts.

## MITRE ATT&CK

- T1012

## Analytic Stories

- China-Nexus Threat Activity
- SnappyBee
- RedLine Stealer
- Salt Typhoon

## Data Sources

- Windows Event Log Security 4663

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/redline/browser_list/ar3_4663_redline_reg.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_query_registry_browser_list_application.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
