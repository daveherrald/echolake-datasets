# AWS Exfiltration via Bucket Replication

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

The following analytic detects API calls to enable S3 bucket replication services. It leverages AWS CloudTrail logs to identify `PutBucketReplication` events, focusing on fields like `bucketName`, `ReplicationConfiguration.Rule.Destination.Bucket`, and user details. This activity is significant as it can indicate unauthorized data replication, potentially leading to data exfiltration. If confirmed malicious, attackers could replicate sensitive data to external accounts, leading to data breaches and compliance violations.

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
