# AWS IAM Failure Group Deletion

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying failed attempts to delete AWS IAM groups. It leverages AWS CloudTrail logs to detect events where the DeleteGroup action fails due to errors like NoSuchEntityException, DeleteConflictException, or AccessDenied. This activity is significant as it may indicate unauthorized attempts to modify IAM group configurations, which could be a precursor to privilege escalation or other malicious actions. If confirmed malicious, this could allow an attacker to disrupt IAM policies, potentially leading to unauthorized access or denial of service within the AWS environment.

## MITRE ATT&CK

- T1098

## Analytic Stories

- AWS IAM Privilege Escalation

## Data Sources

- AWS CloudTrail DeleteGroup

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/aws_iam_failure_group_deletion/aws_iam_failure_group_deletion.json


---

*Source: [Splunk Security Content](detections/cloud/aws_iam_failure_group_deletion.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
