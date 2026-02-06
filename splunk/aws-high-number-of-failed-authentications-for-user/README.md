# AWS High Number Of Failed Authentications For User

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

The following analytic detects an AWS account experiencing more than 20 failed authentication attempts within a 5-minute window. It leverages AWS CloudTrail logs to identify multiple failed ConsoleLogin events. This behavior is significant as it may indicate a brute force attack targeting the account. If confirmed malicious, the attacker could potentially gain unauthorized access, leading to data breaches or further exploitation of the AWS environment. Security teams should consider adjusting the threshold based on their specific environment to reduce false positives.

## MITRE ATT&CK

- T1201

## Analytic Stories

- Compromised User Account
- AWS Identity and Access Management Account Takeover

## Data Sources

- AWS CloudTrail ConsoleLogin

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/aws_multiple_login_fail_per_user/cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/aws_high_number_of_failed_authentications_for_user.yml)*
