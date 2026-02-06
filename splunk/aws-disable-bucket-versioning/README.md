# AWS Disable Bucket Versioning

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

The following analytic detects when AWS S3 bucket versioning is suspended by a user. It leverages AWS CloudTrail logs to identify `PutBucketVersioning` events with the `VersioningConfiguration.Status` set to `Suspended`. This activity is significant because disabling versioning can prevent recovery of deleted or modified data, which is a common tactic in ransomware attacks. If confirmed malicious, this action could lead to data loss and hinder recovery efforts, severely impacting data integrity and availability.

## MITRE ATT&CK

- T1490

## Analytic Stories

- Suspicious AWS S3 Activities
- Data Exfiltration

## Data Sources

- AWS CloudTrail PutBucketVersioning

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1490/aws_bucket_version/cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/aws_disable_bucket_versioning.yml)*
