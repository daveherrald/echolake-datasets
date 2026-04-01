# AWS SetDefaultPolicyVersion

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for detecting when a user sets a default policy version in AWS. It leverages AWS CloudTrail logs to identify the `SetDefaultPolicyVersion` event from the IAM service. This activity is significant because attackers may exploit this technique for privilege escalation, especially if previous policy versions grant more extensive permissions than the current one. If confirmed malicious, this could allow an attacker to gain elevated access to AWS resources, potentially leading to unauthorized actions and data breaches.

## MITRE ATT&CK

- T1078.004

## Analytic Stories

- AWS IAM Privilege Escalation

## Data Sources

- AWS CloudTrail SetDefaultPolicyVersion

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/aws_setdefaultpolicyversion/aws_cloudtrail_events.json


---

*Source: [Splunk Security Content](detections/cloud/aws_setdefaultpolicyversion.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
