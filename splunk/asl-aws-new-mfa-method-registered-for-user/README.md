# ASL AWS New MFA Method Registered For User

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic identifies the registration of a new Multi-Factor Authentication (MFA) method for an AWS account, as logged through Amazon Security Lake (ASL). It detects this activity by monitoring the `CreateVirtualMFADevice` API operation within ASL logs. This behavior is significant because adversaries who gain unauthorized access to an AWS account may register a new MFA method to maintain persistence. If confirmed malicious, this activity could allow attackers to secure their access, making it harder to detect and remove their presence from the compromised environment.

## MITRE ATT&CK

- T1556.006

## Analytic Stories

- AWS Identity and Access Management Account Takeover

## Data Sources

- ASL AWS CloudTrail

## Sample Data

- **Source:** aws_asl
  **Sourcetype:** aws:asl
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556.006/aws_new_mfa_method_registered_for_user/asl_ocsf_cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/asl_aws_new_mfa_method_registered_for_user.yml)*
