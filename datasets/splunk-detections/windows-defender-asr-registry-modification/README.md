# Windows Defender ASR Registry Modification

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting modifications to Windows Defender Attack Surface Reduction (ASR) registry settings. It leverages Windows Defender Operational logs, specifically EventCode 5007, to identify changes in ASR rules. This activity is significant because ASR rules are designed to block actions commonly used by malware to exploit systems. Unauthorized modifications to these settings could indicate an attempt to weaken system defenses. If confirmed malicious, this could allow an attacker to bypass security measures, leading to potential system compromise and data breaches.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Windows Attack Surface Reduction

## Data Sources

- Windows Event Log Defender 5007

## Sample Data

- **Source:** WinEventLog:Microsoft-Windows-Windows Defender/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/defender/asr_registry.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_defender_asr_registry_modification.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
