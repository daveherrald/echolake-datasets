# AWS Defense Evasion Stop Logging Cloudtrail

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for detecting `StopLogging` events in AWS CloudTrail logs. It leverages CloudTrail event data to identify when logging is intentionally stopped, excluding console-based actions and focusing on successful attempts. This activity is significant because adversaries may stop logging to evade detection and operate stealthily within the compromised environment. If confirmed malicious, this action could allow attackers to perform further activities without being logged, hindering incident response and forensic investigations, and potentially leading to unauthorized access or data exfiltration.

## MITRE ATT&CK

- T1562.008

## Analytic Stories

- AWS Defense Evasion

## Data Sources

- AWS CloudTrail StopLogging

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.008/stop_delete_cloudtrail/aws_cloudtrail_events.json


---

*Source: [Splunk Security Content](detections/cloud/aws_defense_evasion_stop_logging_cloudtrail.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
