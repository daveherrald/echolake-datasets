# AWS Bedrock High Number List Foundation Model Failures

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for identifying an high number of AccessDenied attempts to list AWS Bedrock foundation models. It leverages AWS CloudTrail logs to detect when a user or service experiences multiple failures when calling the ListFoundationModels API. This activity is significant as it may indicate an adversary performing reconnaissance of available AI models after compromising credentials with limited permissions. Repeated failures could suggest brute force attempts to enumerate accessible resources or misconfigured access controls. If confirmed malicious, this could represent early-stage reconnaissance before attempting to access or manipulate Bedrock models or knowledge bases.

## MITRE ATT&CK

- T1580

## Analytic Stories

- AWS Bedrock Security

## Data Sources

- AWS CloudTrail

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1580/aws_bedrock_list_foundation_model_failures/cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/aws_bedrock_high_number_list_foundation_model_failures.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
