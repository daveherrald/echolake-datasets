# AWS IAM Delete Policy

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the deletion of an IAM policy in AWS. It leverages AWS CloudTrail logs to identify `DeletePolicy` events, excluding those from AWS internal services. This activity is significant as unauthorized policy deletions can disrupt access controls and weaken security postures. If confirmed malicious, an attacker could remove critical security policies, potentially leading to privilege escalation, unauthorized access, or data exfiltration. Monitoring this behavior helps ensure that only authorized changes are made to IAM policies, maintaining the integrity and security of the AWS environment.

## MITRE ATT&CK

- T1098

## Analytic Stories

- AWS IAM Privilege Escalation

## Data Sources

- AWS CloudTrail DeletePolicy

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/aws_iam_delete_policy/aws_iam_delete_policy.json


---

*Source: [Splunk Security Content](detections/cloud/aws_iam_delete_policy.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
