# ASL AWS Credential Access RDS Password reset

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects the resetting of the master user password for an Amazon RDS DB instance. It leverages AWS CloudTrail logs from Amazon Security Lake to identify events where the `ModifyDBInstance` API call includes a new `masterUserPassword` parameter. This activity is significant because unauthorized password resets can grant attackers access to sensitive data stored in production databases, such as credit card information, PII, and healthcare data. If confirmed malicious, this could lead to data breaches, regulatory non-compliance, and significant reputational damage. Immediate investigation is required to determine the legitimacy of the password reset.

## MITRE ATT&CK

- T1110
- T1586.003

## Analytic Stories

- AWS Identity and Access Management Account Takeover
- Scattered Lapsus$ Hunters

## Data Sources

- ASL AWS CloudTrail

## Sample Data

- **Source:** aws_asl
  **Sourcetype:** aws:asl
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.002/aws_rds_password_reset/asl_ocsf_cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/asl_aws_credential_access_rds_password_reset.yml)*
