# Windows AppLocker Rare Application Launch Detection

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the launch of rarely used applications within the environment, which may indicate the use of potentially malicious software or tools by attackers. It leverages Windows AppLocker event logs, aggregating application launch counts over time and flagging those that significantly deviate from the norm. This behavior is significant as it helps identify unusual application activity that could signal a security threat. If confirmed malicious, this activity could allow attackers to execute unauthorized code, potentially leading to further compromise of the system.

## MITRE ATT&CK

- T1218

## Analytic Stories

- Windows AppLocker

## Data Sources


## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-AppLocker/MSI and Script
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562/applocker/applocker.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_applocker_rare_application_launch_detection.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
