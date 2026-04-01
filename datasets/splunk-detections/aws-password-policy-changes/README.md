# AWS Password Policy Changes

**Type:** Hunting

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for detecting successful API calls to view, update, or delete the password policy in an AWS organization. It leverages AWS CloudTrail logs to identify events such as "UpdateAccountPasswordPolicy," "GetAccountPasswordPolicy," and "DeleteAccountPasswordPolicy." This activity is significant because it is uncommon for regular users to perform these actions, and such changes can indicate an adversary attempting to understand or weaken password defenses. If confirmed malicious, this could lead to compromised accounts and increased attack surface, potentially allowing unauthorized access and control over AWS resources.

## MITRE ATT&CK

- T1201

## Analytic Stories

- AWS IAM Privilege Escalation
- Compromised User Account

## Data Sources

- AWS CloudTrail UpdateAccountPasswordPolicy
- AWS CloudTrail GetAccountPasswordPolicy
- AWS CloudTrail DeleteAccountPasswordPolicy

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1201/aws_password_policy/cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/aws_password_policy_changes.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
