# Windows Credentials from Password Stores Chrome Extension Access

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting non-Chrome processes attempting to access the Chrome extensions file. It leverages Windows Security Event logs, specifically event code 4663, to identify this behavior. This activity is significant because adversaries may exploit this file to extract sensitive information from the Chrome browser, posing a security risk. If confirmed malicious, this could lead to unauthorized access to stored credentials and other sensitive data, potentially compromising the security of the affected system and broader network.

## MITRE ATT&CK

- T1012

## Analytic Stories

- StealC Stealer
- DarkGate Malware
- Amadey
- Meduza Stealer
- Malicious Inno Setup Loader
- Phemedrone Stealer
- CISA AA23-347A
- RedLine Stealer
- Braodo Stealer
- MoonPeak
- 0bj3ctivity Stealer

## Data Sources

- Windows Event Log Security 4663

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/redline/browser_ext_access/security-ext-raw.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_credentials_from_password_stores_chrome_extension_access.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
