# AWS Bedrock Delete GuardRails

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

The following analytic identifies attempts to delete AWS Bedrock GuardRails, which are security controls designed to prevent harmful, biased, or inappropriate AI outputs. It leverages AWS CloudTrail logs to detect when a user or service calls the DeleteGuardrail API. This activity is significant as it may indicate an adversary attempting to remove safety guardrails after compromising credentials, potentially to enable harmful or malicious model outputs. Removing guardrails could allow attackers to extract sensitive information, generate offensive content, or bypass security controls designed to prevent prompt injection and other AI-specific attacks. If confirmed malicious, this could represent a deliberate attempt to manipulate model behavior for harmful purposes.

## MITRE ATT&CK

- T1562.008

## Analytic Stories

- AWS Bedrock Security

## Data Sources

- AWS CloudTrail DeleteGuardrail

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.008/aws_bedrock_delete_guardrails/cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/aws_bedrock_delete_guardrails.yml)*
