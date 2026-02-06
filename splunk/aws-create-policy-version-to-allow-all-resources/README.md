# AWS Create Policy Version to allow all resources

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

The following analytic identifies the creation of a new AWS IAM policy version that allows access to all resources. It detects this activity by analyzing AWS CloudTrail logs for the CreatePolicyVersion event with a policy document that grants broad permissions. This behavior is significant because it violates the principle of least privilege, potentially exposing the environment to misuse or abuse. If confirmed malicious, an attacker could gain extensive access to AWS resources, leading to unauthorized actions, data exfiltration, or further compromise of the AWS environment.

## MITRE ATT&CK

- T1078.004

## Analytic Stories

- AWS IAM Privilege Escalation

## Data Sources

- AWS CloudTrail CreatePolicyVersion

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/aws_create_policy_version/aws_cloudtrail_events.json


---

*Source: [Splunk Security Content](detections/cloud/aws_create_policy_version_to_allow_all_resources.yml)*
