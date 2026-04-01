# Detect AWS Console Login by New User

**Type:** Hunting

**Author:** Rico Valdez, Splunk

## Description

This dataset contains sample data for detecting AWS console login events by new users. It leverages AWS CloudTrail events and compares them against a lookup file of previously seen users based on ARN values. This detection is significant because a new user logging into the AWS console could indicate the creation of new accounts or potential unauthorized access. If confirmed malicious, this activity could lead to unauthorized access to AWS resources, data exfiltration, or further exploitation within the cloud environment.

## MITRE ATT&CK

- T1552
- T1586.003

## Analytic Stories

- Suspicious Cloud Authentication Activities
- AWS Identity and Access Management Account Takeover

## Data Sources

- AWS CloudTrail

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json


---

*Source: [Splunk Security Content](detections/cloud/detect_aws_console_login_by_new_user.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
