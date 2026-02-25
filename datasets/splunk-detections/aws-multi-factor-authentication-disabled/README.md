# AWS Multi-Factor Authentication Disabled

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for detecting attempts to disable multi-factor authentication (MFA) for an AWS IAM user. It leverages AWS CloudTrail logs to identify events where MFA devices are deleted or deactivated. This activity is significant because disabling MFA can indicate an adversary attempting to weaken account security, potentially to maintain persistence using a compromised account. If confirmed malicious, this action could allow attackers to retain access to the AWS environment without detection, posing a significant risk to the security and integrity of the cloud infrastructure.

## MITRE ATT&CK

- T1556.006
- T1586.003
- T1621

## Analytic Stories

- AWS Identity and Access Management Account Takeover
- Scattered Lapsus$ Hunters

## Data Sources

- AWS CloudTrail DeleteVirtualMFADevice
- AWS CloudTrail DeactivateMFADevice

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/aws_mfa_disabled/cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/aws_multi_factor_authentication_disabled.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
