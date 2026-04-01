# Windows BitLockerToGo with Network Activity

**Type:** Hunting

**Author:** Michael Haag, Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting suspicious usage of BitLockerToGo.exe, which has been observed being abused by Lumma stealer malware. The malware leverages this legitimate Windows utility to manipulate registry keys, search for cryptocurrency wallets and credentials, and exfiltrate sensitive data. This activity is significant because BitLockerToGo.exe provides functionality for viewing, copying, and writing files as well as modifying registry branches - capabilities that the Lumma stealer exploits for malicious purposes. If confirmed malicious, this could indicate an active data theft campaign targeting cryptocurrency wallets, browser credentials, and password manager archives. The detection focuses on identifying BitLockerToGo.exe execution patterns that deviate from normal system behavior.

## MITRE ATT&CK

- T1218

## Analytic Stories

- Lumma Stealer
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 22

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218/bitlockertogo/bitlockertogo_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_bitlockertogo_with_network_activity.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
