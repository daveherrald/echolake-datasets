# ASL AWS IAM Successful Group Deletion

**Type:** Hunting

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects the successful deletion of a group within AWS IAM, leveraging CloudTrail IAM events. This action, while not inherently malicious, can serve as a precursor to more sinister activities, such as unauthorized access or privilege escalation attempts. By monitoring for such deletions, the analytic aids in identifying potential preparatory steps towards an attack, allowing for early detection and mitigation. The identification of this behavior is crucial for a SOC to prevent the potential impact of an attack, which could include unauthorized access to sensitive resources or disruption of AWS environment operations.

## MITRE ATT&CK

- T1069.003
- T1098

## Analytic Stories

- AWS IAM Privilege Escalation

## Data Sources

- ASL AWS CloudTrail

## Sample Data

- **Source:** aws_asl
  **Sourcetype:** aws:asl
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/aws_iam_successful_group_deletion/asl_ocsf_cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/asl_aws_iam_successful_group_deletion.yml)*
