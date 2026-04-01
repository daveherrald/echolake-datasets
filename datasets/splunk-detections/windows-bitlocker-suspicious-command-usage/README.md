# Windows BitLocker Suspicious Command Usage

**Type:** TTP

**Author:** Steven Dick

## Description

This analytic is developed to detect the usage of BitLocker commands used to disable or impact boot settings. The malware ShrinkLocker uses various commands change how BitLocker handles encryption, potentially bypassing TPM requirements, enabling BitLocker without TPM, and enforcing specific startup key and PIN configurations. Such modifications can weaken system security, making it easier for unauthorized access and data breaches. Detecting these changes is crucial for maintaining robust encryption and data protection.

## MITRE ATT&CK

- T1486
- T1490

## Analytic Stories

- ShrinkLocker

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1486/bitlocker_sus_commands/bitlocker_sus_commands.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_bitlocker_suspicious_command_usage.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
