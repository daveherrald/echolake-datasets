# AWS AMI Attribute Modification for Exfiltration

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

The following analytic detects suspicious modifications to AWS AMI attributes, such as sharing an AMI with another AWS account or making it publicly accessible. It leverages AWS CloudTrail logs to identify these changes by monitoring specific API calls. This activity is significant because adversaries can exploit these modifications to exfiltrate sensitive data stored in AWS resources. If confirmed malicious, this could lead to unauthorized access and potential data breaches, compromising the confidentiality and integrity of organizational information.

## MITRE ATT&CK

- T1537

## Analytic Stories

- Suspicious Cloud Instance Activities
- Data Exfiltration

## Data Sources

- AWS CloudTrail ModifyImageAttribute

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1537/aws_ami_shared_public/aws_cloudtrail_events.json


---

*Source: [Splunk Security Content](detections/cloud/aws_ami_attribute_modification_for_exfiltration.yml)*
