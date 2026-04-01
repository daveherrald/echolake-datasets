# AWS Defense Evasion PutBucketLifecycle

**Type:** Hunting

**Author:** Bhavin Patel

## Description

This dataset contains sample data for detecting `PutBucketLifecycle` events in AWS CloudTrail logs where a user sets a lifecycle rule for an S3 bucket with an expiration period of fewer than three days. This detection leverages CloudTrail logs to identify suspicious lifecycle configurations. This activity is significant because attackers may use it to delete CloudTrail logs quickly, thereby evading detection and impairing forensic investigations. If confirmed malicious, this could allow attackers to cover their tracks, making it difficult to trace their actions and respond to the breach effectively.

## MITRE ATT&CK

- T1485.001
- T1562.008

## Analytic Stories

- AWS Defense Evasion

## Data Sources

- AWS CloudTrail PutBucketLifecycle

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.008/put_bucketlifecycle/aws_cloudtrail_events.json


---

*Source: [Splunk Security Content](detections/cloud/aws_defense_evasion_putbucketlifecycle.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
