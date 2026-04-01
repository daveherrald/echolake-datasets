# AWS Defense Evasion Delete Cloudtrail

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for detecting the deletion of AWS CloudTrail logs by identifying `DeleteTrail` events within CloudTrail logs. This detection leverages CloudTrail data to monitor for successful `DeleteTrail` actions, excluding those initiated from the AWS console. This activity is significant because adversaries may delete CloudTrail logs to evade detection and operate stealthily within the compromised environment. If confirmed malicious, this action could allow attackers to cover their tracks, making it difficult to trace their activities and potentially leading to prolonged unauthorized access and further exploitation.

## MITRE ATT&CK

- T1562.008

## Analytic Stories

- AWS Defense Evasion

## Data Sources

- AWS CloudTrail DeleteTrail

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.008/stop_delete_cloudtrail/aws_cloudtrail_events.json


---

*Source: [Splunk Security Content](detections/cloud/aws_defense_evasion_delete_cloudtrail.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
