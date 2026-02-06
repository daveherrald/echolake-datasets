# AWS UpdateLoginProfile

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

The following analytic detects an AWS CloudTrail event where a user with permissions updates the login profile of another user. It leverages CloudTrail logs to identify instances where the user making the change is different from the user whose profile is being updated. This activity is significant because it can indicate privilege escalation attempts, where an attacker uses a compromised account to gain higher privileges. If confirmed malicious, this could allow the attacker to escalate their privileges, potentially leading to unauthorized access and control over sensitive resources within the AWS environment.

## MITRE ATT&CK

- T1136.003

## Analytic Stories

- AWS IAM Privilege Escalation

## Data Sources

- AWS CloudTrail UpdateLoginProfile

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/aws_updateloginprofile/aws_cloudtrail_events.json


---

*Source: [Splunk Security Content](detections/cloud/aws_updateloginprofile.yml)*
