# AWS Lambda UpdateFunctionCode

**Type:** Hunting

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for identifying IAM users attempting to update or modify AWS Lambda code via the AWS CLI. It leverages CloudTrail logs to detect successful `UpdateFunctionCode` events initiated by IAM users. This activity is significant as it may indicate an attempt to gain persistence, further access, or plant backdoors within your AWS environment. If confirmed malicious, an attacker could upload and execute malicious code automatically when the Lambda function is triggered, potentially compromising the integrity and security of your AWS infrastructure.

## MITRE ATT&CK

- T1204

## Analytic Stories

- Suspicious Cloud User Activities

## Data Sources

- AWS CloudTrail

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1204/aws_updatelambdafunctioncode/aws_cloudtrail_events.json


---

*Source: [Splunk Security Content](detections/cloud/aws_lambda_updatefunctioncode.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
