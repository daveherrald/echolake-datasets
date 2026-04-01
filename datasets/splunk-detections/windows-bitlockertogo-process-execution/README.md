# Windows BitLockerToGo Process Execution

**Type:** Hunting

**Author:** Michael Haag, Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting BitLockerToGo.exe execution, which has been observed being abused by Lumma stealer malware. The malware leverages this legitimate Windows utility to manipulate registry keys, search for cryptocurrency wallets and credentials, and exfiltrate sensitive data. This activity is significant because BitLockerToGo.exe provides functionality for viewing, copying, and writing files as well as modifying registry branches - capabilities that the Lumma stealer exploits. However, note that if legitimate use of BitLockerToGo.exe is in the organization, this detection will

## MITRE ATT&CK

- T1218

## Analytic Stories

- Lumma Stealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218/bitlockertogo/4688_bitlockertogo_windows-security.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_bitlockertogo_process_execution.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
