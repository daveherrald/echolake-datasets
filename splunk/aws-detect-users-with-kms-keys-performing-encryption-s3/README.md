# AWS Detect Users with KMS keys performing encryption S3

**Type:** Anomaly

**Author:** Rod Soto, Patrick Bareiss Splunk

## Description

The following analytic identifies users with KMS keys performing encryption operations on S3 buckets. It leverages AWS CloudTrail logs to detect the `CopyObject` event where server-side encryption with AWS KMS is specified. This activity is significant as it may indicate unauthorized or suspicious encryption of data, potentially masking exfiltration or tampering efforts. If confirmed malicious, an attacker could be encrypting sensitive data to evade detection or preparing it for exfiltration, posing a significant risk to data integrity and confidentiality.

## MITRE ATT&CK

- T1486

## Analytic Stories

- Ransomware Cloud

## Data Sources

- AWS CloudTrail

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1486/s3_file_encryption/aws_cloudtrail_events.json


---

*Source: [Splunk Security Content](detections/cloud/aws_detect_users_with_kms_keys_performing_encryption_s3.yml)*
