# ASL AWS Detect Users creating keys with encrypt policy without MFA

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects the creation of AWS KMS keys with an encryption policy accessible to everyone, including external entities. It leverages AWS CloudTrail logs from Amazon Security Lake to identify `CreateKey` or `PutKeyPolicy` events where the `kms:Encrypt` action is granted to all principals. This activity is significant as it may indicate a compromised account, allowing an attacker to misuse the encryption key to target other organizations. If confirmed malicious, this could lead to unauthorized data encryption, potentially disrupting operations and compromising sensitive information across multiple entities.

## MITRE ATT&CK

- T1486

## Analytic Stories

- Ransomware Cloud

## Data Sources

- ASL AWS CloudTrail

## Sample Data

- **Source:** aws_asl
  **Sourcetype:** aws:asl
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1486/aws_kms_key/asl_ocsf_cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/asl_aws_detect_users_creating_keys_with_encrypt_policy_without_mfa.yml)*
