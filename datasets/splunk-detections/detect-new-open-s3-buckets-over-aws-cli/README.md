# Detect New Open S3 Buckets over AWS CLI

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting the creation of open/public S3 buckets via the AWS CLI. It leverages AWS CloudTrail logs to identify events where a user has set bucket permissions to allow access to "AuthenticatedUsers" or "AllUsers." This activity is significant because open S3 buckets can expose sensitive data to unauthorized users, leading to data breaches. If confirmed malicious, an attacker could gain unauthorized access to potentially sensitive information stored in the S3 bucket, posing a significant security risk.

## MITRE ATT&CK

- T1530

## Analytic Stories

- Suspicious AWS S3 Activities

## Data Sources

- AWS CloudTrail

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1530/aws_s3_public_bucket/aws_cloudtrail_events.json


---

*Source: [Splunk Security Content](detections/cloud/detect_new_open_s3_buckets_over_aws_cli.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
