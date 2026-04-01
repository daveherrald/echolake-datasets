# AWS Exfiltration via Bucket Replication

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for detecting API calls to enable S3 bucket replication services. It leverages AWS CloudTrail logs to identify `PutBucketReplication` events, focusing on fields like `bucketName`, `ReplicationConfiguration.Rule.Destination.Bucket`, and user details. This activity is significant as it can indicate unauthorized data replication, potentially leading to data exfiltration. If confirmed malicious, attackers could replicate sensitive data to external accounts, leading to data breaches and compliance violations.

## MITRE ATT&CK

- T1537

## Analytic Stories

- Suspicious AWS S3 Activities
- Data Exfiltration

## Data Sources

- AWS CloudTrail PutBucketReplication

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1119/aws_exfil_datasync/cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/aws_exfiltration_via_bucket_replication.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
