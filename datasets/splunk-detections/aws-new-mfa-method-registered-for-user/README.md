# AWS New MFA Method Registered For User

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for detecting the registration of a new Multi-Factor Authentication (MFA) method for an AWS account. It leverages AWS CloudTrail logs to identify the `CreateVirtualMFADevice` event. This activity is significant because adversaries who gain unauthorized access to an AWS account may register a new MFA method to maintain persistence. If confirmed malicious, this could allow attackers to secure their access, making it difficult to detect and remove their presence, potentially leading to further unauthorized activities and data breaches.

## MITRE ATT&CK

- T1556.006

## Analytic Stories

- AWS Identity and Access Management Account Takeover

## Data Sources

- AWS CloudTrail CreateVirtualMFADevice

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556.006/aws_new_mfa_method_registered_for_user/cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/aws_new_mfa_method_registered_for_user.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
