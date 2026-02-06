# AWS Bedrock Invoke Model Access Denied

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

The following analytic identifies access denied error when attempting to invoke AWS Bedrock models. It leverages AWS CloudTrail logs to detect when a user or service receives an AccessDenied error when calling the InvokeModel API. This activity is significant as it may indicate an adversary attempting to access Bedrock models with insufficient permissions after compromising credentials. If confirmed malicious, this could suggest reconnaissance activities or privilege escalation attempts targeting generative AI resources, potentially leading to data exfiltration or manipulation of model outputs.

## MITRE ATT&CK

- T1078
- T1550

## Analytic Stories

- AWS Bedrock Security

## Data Sources

- AWS CloudTrail

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.004/aws_invoke_model_access_denied/cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/aws_bedrock_invoke_model_access_denied.yml)*
