# AWS Multiple Failed MFA Requests For User

**Type:** Anomaly

**Author:** Bhavin Patel

## Description

This dataset contains sample data for identifying multiple failed multi-factor authentication (MFA) requests to an AWS Console for a single user. It leverages AWS CloudTrail logs, specifically the `additionalEventData` field, to detect more than 10 failed MFA prompts within 5 minutes. This activity is significant as it may indicate an adversary attempting to bypass MFA by bombarding the user with repeated authentication requests. If confirmed malicious, this could lead to unauthorized access to the AWS environment, potentially compromising sensitive data and resources.

## MITRE ATT&CK

- T1586.003
- T1621

## Analytic Stories

- AWS Identity and Access Management Account Takeover

## Data Sources

- AWS CloudTrail ConsoleLogin

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/aws_failed_mfa/cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/aws_multiple_failed_mfa_requests_for_user.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
