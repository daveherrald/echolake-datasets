# AWS Bedrock Delete Knowledge Base

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for identifying attempts to delete AWS Bedrock Knowledge Bases, which are resources that store and manage domain-specific information for AI models. It monitors AWS CloudTrail logs for DeleteKnowledgeBase API calls. This activity could indicate an adversary attempting to remove knowledge bases after compromising credentials, potentially to disrupt business operations or remove traces of data access. Deleting knowledge bases could impact model performance, remove critical business context, or be part of a larger attack to degrade AI capabilities. If confirmed malicious, this could represent a deliberate attempt to cause service disruption or data loss.

## MITRE ATT&CK

- T1485

## Analytic Stories

- AWS Bedrock Security

## Data Sources

- AWS CloudTrail DeleteKnowledgeBase

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1485/aws_delete_knowledge_base/cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/aws_bedrock_delete_knowledge_base.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
