# Windows AppLocker Block Events

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting attempts to bypass application restrictions by identifying Windows AppLocker policy violations. It leverages Windows AppLocker event logs, specifically EventCodes 8007, 8004, 8022, 8025, 8029, and 8040, to pinpoint blocked actions. This activity is significant for a SOC as it highlights potential unauthorized application executions, which could indicate malicious intent or policy circumvention. If confirmed malicious, this activity could allow an attacker to execute unauthorized applications, potentially leading to further system compromise or data exfiltration.

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

*Source: [Splunk Security Content](detections/endpoint/windows_applocker_block_events.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
