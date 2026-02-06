# AWS Exfiltration via Anomalous GetObject API Activity

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

The following analytic identifies anomalous GetObject API activity in AWS, indicating potential data exfiltration attempts. It leverages AWS CloudTrail logs and uses the `anomalydetection` command to detect unusual patterns in the frequency of GetObject API calls by analyzing fields such as "count," "user_type," and "user_arn" within a 10-minute window. This activity is significant as it may indicate unauthorized data access or exfiltration from S3 buckets. If confirmed malicious, attackers could exfiltrate sensitive data, leading to data breaches and compliance violations.

## MITRE ATT&CK

- T1119

## Analytic Stories

- Data Exfiltration

## Data Sources

- AWS CloudTrail GetObject

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1530/aws_exfil_high_no_getobject/cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/aws_exfiltration_via_anomalous_getobject_api_activity.yml)*
