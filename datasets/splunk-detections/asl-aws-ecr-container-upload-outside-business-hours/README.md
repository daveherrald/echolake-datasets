# ASL AWS ECR Container Upload Outside Business Hours

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting the upload of new containers to AWS Elastic Container Service (ECR) outside of standard business hours through AWS CloudTrail events. It identifies this behavior by monitoring for `PutImage` events occurring before 8 AM or after 8 PM, as well as any uploads on weekends. This activity is significant for a SOC to investigate as it may indicate unauthorized access or malicious deployments, potentially leading to compromised services or data breaches. Identifying and addressing such uploads promptly can mitigate the risk of security incidents and their associated impacts.

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

*Source: [Splunk Security Content](detections/cloud/asl_aws_ecr_container_upload_outside_business_hours.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
