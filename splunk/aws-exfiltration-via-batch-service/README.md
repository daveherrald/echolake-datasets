# AWS Exfiltration via Batch Service

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

The following analytic identifies the creation of AWS Batch jobs that could potentially abuse the AWS Bucket Replication feature on S3 buckets. It leverages AWS CloudTrail logs to detect the `JobCreated` event, analyzing job details and their status. This activity is significant because attackers can exploit this feature to exfiltrate data by creating malicious batch jobs. If confirmed malicious, this could lead to unauthorized data transfer between S3 buckets, resulting in data breaches and loss of sensitive information.

## MITRE ATT&CK

- T1119

## Analytic Stories

- Data Exfiltration

## Data Sources

- AWS CloudTrail JobCreated

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1119/aws_exfil_datasync/cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/aws_exfiltration_via_batch_service.yml)*
