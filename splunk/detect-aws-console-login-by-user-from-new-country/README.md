# Detect AWS Console Login by User from New Country

**Type:** Hunting

**Author:** Bhavin Patel, Eric McGinnis Splunk

## Description

The following analytic identifies AWS console login events by users from a new country. It leverages AWS CloudTrail events and compares them against a lookup file of previously seen users and their login locations. This activity is significant because logins from new countries can indicate potential unauthorized access or compromised accounts. If confirmed malicious, this could lead to unauthorized access to AWS resources, data exfiltration, or further exploitation within the AWS environment.

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

*Source: [Splunk Security Content](detections/cloud/detect_aws_console_login_by_user_from_new_country.yml)*
