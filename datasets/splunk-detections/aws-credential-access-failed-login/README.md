# AWS Credential Access Failed Login

**Type:** TTP

**Author:** Gowthamaraj Rajendran, Bhavin Patel, Splunk

## Description

This dataset contains sample data for identifying unsuccessful login attempts to the AWS Management Console using a specific user identity. It leverages AWS CloudTrail logs to detect failed authentication events associated with the AWS ConsoleLogin action. This activity is significant for a SOC because repeated failed login attempts may indicate a brute force attack or unauthorized access attempts. If confirmed malicious, an attacker could potentially gain access to AWS account services and resources, leading to data breaches, resource manipulation, or further exploitation within the AWS environment.

## MITRE ATT&CK

- T1110.001
- T1586.003

## Analytic Stories

- AWS Identity and Access Management Account Takeover

## Data Sources

- AWS CloudTrail ConsoleLogin

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.001/aws_login_failure/aws_cloudtrail_events.json


---

*Source: [Splunk Security Content](detections/cloud/aws_credential_access_failed_login.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
