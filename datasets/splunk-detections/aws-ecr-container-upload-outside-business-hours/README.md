# AWS ECR Container Upload Outside Business Hours

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting the upload of a new container image to AWS Elastic Container Registry (ECR) outside of standard business hours. It leverages AWS CloudTrail logs to identify `PutImage` events occurring between 8 PM and 8 AM or on weekends. This activity is significant because container uploads outside business hours can indicate unauthorized or suspicious activity, potentially pointing to a compromised account or insider threat. If confirmed malicious, this could allow an attacker to deploy unauthorized or malicious containers, leading to potential data breaches or service disruptions.

## MITRE ATT&CK

- T1204.003

## Analytic Stories

- Dev Sec Ops

## Data Sources

- AWS CloudTrail PutImage

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1204.003/aws_ecr_container_upload/aws_ecr_container_upload.json


---

*Source: [Splunk Security Content](detections/cloud/aws_ecr_container_upload_outside_business_hours.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
