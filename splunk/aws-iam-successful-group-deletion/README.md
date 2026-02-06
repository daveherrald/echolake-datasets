# AWS IAM Successful Group Deletion

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies the successful deletion of an IAM group in AWS. It leverages CloudTrail logs to detect `DeleteGroup` events with a success status. This activity is significant as it could indicate potential changes in user permissions or access controls, which may be a precursor to further unauthorized actions. If confirmed malicious, an attacker could disrupt access management, potentially leading to privilege escalation or unauthorized access to sensitive resources. Analysts should review related IAM events, such as recent user additions or new group creations, to assess the broader context.

## MITRE ATT&CK

- T1069.003
- T1098

## Analytic Stories

- AWS IAM Privilege Escalation

## Data Sources

- AWS CloudTrail DeleteGroup

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/aws_iam_successful_group_deletion/aws_iam_successful_group_deletion.json


---

*Source: [Splunk Security Content](detections/cloud/aws_iam_successful_group_deletion.yml)*
