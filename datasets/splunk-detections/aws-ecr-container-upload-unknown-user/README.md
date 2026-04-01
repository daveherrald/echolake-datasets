# AWS ECR Container Upload Unknown User

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting the upload of a new container image to AWS Elastic Container Registry (ECR) by an unknown user. It leverages AWS CloudTrail logs to identify `PutImage` events from the ECR service, filtering out known users. This activity is significant because container uploads should typically be performed by a limited set of authorized users. If confirmed malicious, this could indicate unauthorized access, potentially leading to the deployment of malicious containers, data exfiltration, or further compromise of the AWS environment.

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

*Source: [Splunk Security Content](detections/cloud/aws_ecr_container_upload_unknown_user.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
