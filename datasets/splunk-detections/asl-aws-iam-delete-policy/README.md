# ASL AWS IAM Delete Policy

**Type:** Hunting

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for identifying when a policy is deleted in AWS. It leverages Amazon Security Lake logs to detect the DeletePolicy API operation. Monitoring policy deletions is crucial as it can indicate unauthorized attempts to weaken security controls. If confirmed malicious, this activity could allow an attacker to remove critical security policies, potentially leading to privilege escalation or unauthorized access to sensitive resources.

## MITRE ATT&CK

- T1098

## Analytic Stories

- AWS IAM Privilege Escalation

## Data Sources

- ASL AWS CloudTrail

## Sample Data

- **Source:** aws_asl
  **Sourcetype:** aws:asl
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/aws_iam_delete_policy/asl_ocsf_cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/asl_aws_iam_delete_policy.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
