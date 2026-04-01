# Cloud Security Groups Modifications by User

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for identifying unusual modifications to security groups in your cloud environment by users, focusing on actions such as modifications, deletions, or creations over 30-minute intervals. It leverages cloud infrastructure logs and calculates the standard deviation for each user, using the 3-sigma rule to detect anomalies. This activity is significant as it may indicate a compromised account or insider threat. If confirmed malicious, attackers could alter security group configurations, potentially exposing sensitive resources or disrupting services.

## MITRE ATT&CK

- T1578.005

## Analytic Stories

- Suspicious Cloud User Activities

## Data Sources

- AWS CloudTrail

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1578.005/aws_authorize_security_group/aws_authorize_security_group.json


---

*Source: [Splunk Security Content](detections/cloud/cloud_security_groups_modifications_by_user.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
