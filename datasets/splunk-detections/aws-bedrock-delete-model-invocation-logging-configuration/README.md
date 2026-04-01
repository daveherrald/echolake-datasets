# AWS Bedrock Delete Model Invocation Logging Configuration

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for identifying attempts to delete AWS Bedrock model invocation logging configurations. It leverages AWS CloudTrail logs to detect when a user or service calls the DeleteModelInvocationLogging API. This activity is significant as it may indicate an adversary attempting to remove audit trails of model interactions after compromising credentials. Deleting model invocation logs could allow attackers to interact with AI models without leaving traces, potentially enabling them to conduct data exfiltration, prompt injection attacks, or other malicious activities without detection. If confirmed malicious, this could represent a deliberate attempt to hide unauthorized model usage and evade detection.

## MITRE ATT&CK

- T1562.008

## Analytic Stories

- AWS Bedrock Security

## Data Sources

- AWS CloudTrail DeleteModelInvocationLoggingConfiguration

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.008/aws_bedrock_delete_model_invocation_logging/cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/aws_bedrock_delete_model_invocation_logging_configuration.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
