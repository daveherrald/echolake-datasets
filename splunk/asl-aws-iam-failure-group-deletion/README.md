# ASL AWS IAM Failure Group Deletion

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects failed attempts to delete AWS IAM groups, triggered by access denial, conflicts, or non-existent groups. It operates by monitoring CloudTrail logs for specific error codes related to deletion failures. This behavior is significant for a SOC as it may indicate unauthorized attempts to modify access controls or disrupt operations by removing groups. Such actions could be part of a larger attack aiming to escalate privileges or impair security protocols. Identifying these attempts allows for timely investigation and mitigation, preventing potential impact on the organizations security posture.

## MITRE ATT&CK

- T1098

## Analytic Stories

- AWS IAM Privilege Escalation

## Data Sources

- ASL AWS CloudTrail

## Sample Data

- **Source:** aws_asl
  **Sourcetype:** aws:asl
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/aws_iam_failure_group_deletion/asl_ocsf_cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/asl_aws_iam_failure_group_deletion.yml)*
