# ASL AWS Multi-Factor Authentication Disabled

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects attempts to disable multi-factor authentication (MFA) for an AWS IAM user. It leverages Amazon Security Lake logs, specifically monitoring for `DeleteVirtualMFADevice` or `DeactivateMFADevice` API operations. This activity is significant as disabling MFA can indicate an adversary attempting to weaken account security to maintain persistence using a compromised account. If confirmed malicious, this action could allow attackers to retain access to the AWS environment without detection, potentially leading to unauthorized access to sensitive resources and prolonged compromise.

## MITRE ATT&CK

- T1556.006
- T1586.003
- T1621

## Analytic Stories

- AWS Identity and Access Management Account Takeover

## Data Sources

- ASL AWS CloudTrail

## Sample Data

- **Source:** aws_asl
  **Sourcetype:** aws:asl
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/aws_mfa_disabled/asl_ocsf_cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/asl_aws_multi_factor_authentication_disabled.yml)*
