# AWS Credential Access GetPasswordData

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

The following analytic identifies more than 10 GetPasswordData API calls within a 5-minute window in your AWS account. It leverages AWS CloudTrail logs to detect this activity by counting the distinct instance IDs accessed. This behavior is significant as it may indicate an attempt to retrieve encrypted administrator passwords for running Windows instances, which is a critical security concern. If confirmed malicious, attackers could gain unauthorized access to administrative credentials, potentially leading to full control over the affected instances and further compromise of the AWS environment.

## MITRE ATT&CK

- T1110.001
- T1586.003

## Analytic Stories

- AWS Identity and Access Management Account Takeover

## Data Sources

- AWS CloudTrail GetPasswordData

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552/aws_getpassworddata/aws_cloudtrail_events.json


---

*Source: [Splunk Security Content](detections/cloud/aws_credential_access_getpassworddata.yml)*
