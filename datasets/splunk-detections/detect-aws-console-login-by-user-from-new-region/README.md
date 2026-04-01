# Detect AWS Console Login by User from New Region

**Type:** Hunting

**Author:** Bhavin Patel, Eric McGinnis Splunk

## Description

This dataset contains sample data for identifying AWS console login attempts by users from a new region. It leverages AWS CloudTrail events and compares current login regions against a baseline of previously seen regions for each user. This activity is significant as it may indicate unauthorized access attempts or compromised credentials. If confirmed malicious, an attacker could gain unauthorized access to AWS resources, potentially leading to data breaches, resource manipulation, or further lateral movement within the cloud environment.

## MITRE ATT&CK

- T1535
- T1586.003

## Analytic Stories

- Suspicious AWS Login Activities
- Suspicious Cloud Authentication Activities
- AWS Identity and Access Management Account Takeover
- Compromised User Account

## Data Sources

- AWS CloudTrail

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json


---

*Source: [Splunk Security Content](detections/cloud/detect_aws_console_login_by_user_from_new_region.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
