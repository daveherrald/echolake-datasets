# ASL AWS SAML Update identity provider

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects updates to the SAML provider in AWS. It leverages AWS CloudTrail logs to identify the `UpdateSAMLProvider` event, analyzing fields such as `sAMLProviderArn`, `sourceIPAddress`, and `userIdentity` details. Monitoring updates to the SAML provider is crucial as it may indicate a perimeter compromise of federated credentials or unauthorized backdoor access set by an attacker. If confirmed malicious, this activity could allow attackers to manipulate identity federation, potentially leading to unauthorized access to cloud resources and sensitive data.

## MITRE ATT&CK

- T1078

## Analytic Stories

- Cloud Federated Credential Abuse

## Data Sources

- ASL AWS CloudTrail

## Sample Data

- **Source:** aws_asl
  **Sourcetype:** aws:asl
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/update_saml_provider/asl_ocsf_cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/asl_aws_saml_update_identity_provider.yml)*
