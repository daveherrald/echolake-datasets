# AWS IAM Assume Role Policy Brute Force

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting multiple failed attempts to assume an AWS IAM role, indicating a potential brute force attack. It leverages AWS CloudTrail logs to identify `MalformedPolicyDocumentException` errors with a status of `failure` and filters out legitimate AWS services. This activity is significant as repeated failures to assume roles can indicate an adversary attempting to guess role names, which is a precursor to unauthorized access. If confirmed malicious, this could lead to unauthorized access to AWS resources, potentially compromising sensitive data and services.

## MITRE ATT&CK

- T1580
- T1110

## Analytic Stories

- AWS IAM Privilege Escalation

## Data Sources

- AWS CloudTrail

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1580/aws_iam_assume_role_policy_brute_force/aws_iam_assume_role_policy_brute_force.json


---

*Source: [Splunk Security Content](detections/cloud/aws_iam_assume_role_policy_brute_force.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
