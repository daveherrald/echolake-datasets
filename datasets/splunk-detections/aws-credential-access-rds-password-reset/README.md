# AWS Credential Access RDS Password reset

**Type:** TTP

**Author:** Gowthamaraj Rajendran, Splunk

## Description

This dataset contains sample data for detecting the resetting of the master user password for an Amazon RDS DB instance. It leverages AWS CloudTrail logs to identify events where the `ModifyDBInstance` API call includes a new `masterUserPassword` parameter. This activity is significant because unauthorized password resets can grant attackers access to sensitive data stored in production databases, such as credit card information, PII, and healthcare data. If confirmed malicious, this could lead to data breaches, regulatory non-compliance, and significant reputational damage. Immediate investigation is required to determine the legitimacy of the password reset.

## MITRE ATT&CK

- T1110
- T1586.003

## Analytic Stories

- AWS Identity and Access Management Account Takeover
- Scattered Lapsus$ Hunters

## Data Sources

- AWS CloudTrail ModifyDBInstance

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.002/aws_rds_password_reset/aws_cloudtrail_events.json


---

*Source: [Splunk Security Content](detections/cloud/aws_credential_access_rds_password_reset.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
