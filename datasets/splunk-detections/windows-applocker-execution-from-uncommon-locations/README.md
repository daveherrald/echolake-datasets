# Windows AppLocker Execution from Uncommon Locations

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying the execution of applications or scripts from uncommon or suspicious file paths, potentially indicating malware or unauthorized activity. It leverages Windows AppLocker event logs and uses statistical analysis to detect anomalies. By calculating the average and standard deviation of execution counts per file path, it flags paths with execution counts significantly higher than expected. This behavior is significant as it can uncover malicious activities or policy violations. If confirmed malicious, this activity could allow attackers to execute unauthorized code, leading to potential system compromise or data breaches.

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

*Source: [Splunk Security Content](detections/endpoint/windows_applocker_execution_from_uncommon_locations.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
