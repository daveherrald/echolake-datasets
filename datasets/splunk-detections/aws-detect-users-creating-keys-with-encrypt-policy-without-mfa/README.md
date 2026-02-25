# AWS Detect Users creating keys with encrypt policy without MFA

**Type:** TTP

**Author:** Rod Soto, Patrick Bareiss Splunk

## Description

This dataset contains sample data for detecting the creation of AWS KMS keys with an encryption policy accessible to everyone, including external entities. It leverages AWS CloudTrail logs to identify `CreateKey` or `PutKeyPolicy` events where the `kms:Encrypt` action is granted to all principals. This activity is significant as it may indicate a compromised account, allowing an attacker to misuse the encryption key to target other organizations. If confirmed malicious, this could lead to unauthorized data encryption, potentially disrupting operations and compromising sensitive information across multiple entities.

## MITRE ATT&CK

- T1486

## Analytic Stories

- Ransomware Cloud

## Data Sources

- AWS CloudTrail CreateKey
- AWS CloudTrail PutKeyPolicy

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1486/aws_kms_key/aws_cloudtrail_events.json


---

*Source: [Splunk Security Content](detections/cloud/aws_detect_users_creating_keys_with_encrypt_policy_without_mfa.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
