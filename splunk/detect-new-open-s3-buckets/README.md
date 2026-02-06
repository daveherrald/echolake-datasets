# Detect New Open S3 buckets

**Type:** TTP

**Author:** Bhavin Patel, Patrick Bareiss, Splunk

## Description

The following analytic identifies the creation of open/public S3 buckets in AWS. It detects this activity by analyzing AWS CloudTrail events for `PutBucketAcl` actions where the access control list (ACL) grants permissions to all users or authenticated users. This activity is significant because open S3 buckets can expose sensitive data to unauthorized access, leading to data breaches. If confirmed malicious, an attacker could read, write, or fully control the contents of the bucket, potentially leading to data exfiltration or tampering.

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

*Source: [Splunk Security Content](detections/cloud/detect_new_open_s3_buckets.yml)*
