# ASL AWS ECR Container Upload Unknown User

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting unauthorized container uploads to AWS Elastic Container Service (ECR) by monitoring AWS CloudTrail events. It identifies instances where a new container is uploaded by a user not previously recognized as authorized. This detection is crucial for a SOC as it can indicate a potential compromise or misuse of AWS ECR, which could lead to unauthorized access to sensitive data or the deployment of malicious containers. By identifying and investigating these events, organizations can mitigate the risk of data breaches or other security incidents resulting from unauthorized container uploads. The impact of such an attack could be significant, compromising the integrity and security of the organization's cloud environment.

## MITRE ATT&CK

- T1204.003

## Analytic Stories

- Dev Sec Ops

## Data Sources

- ASL AWS CloudTrail

## Sample Data

- **Source:** aws_asl
  **Sourcetype:** aws:asl
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1204.003/aws_ecr_container_upload/asl_ocsf_cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/asl_aws_ecr_container_upload_unknown_user.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
