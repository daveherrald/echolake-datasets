# AWS Successful Single-Factor Authentication

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for identifying a successful Console Login authentication event for an AWS IAM user account without Multi-Factor Authentication (MFA) enabled. It leverages AWS CloudTrail logs to detect instances where MFA was not used during login. This activity is significant as it may indicate a misconfiguration, policy violation, or potential account takeover attempt. If confirmed malicious, an attacker could gain unauthorized access to the AWS environment, potentially leading to data exfiltration, resource manipulation, or further privilege escalation.

## MITRE ATT&CK

- T1078.004
- T1586.003

## Analytic Stories

- AWS Identity and Access Management Account Takeover

## Data Sources

- AWS CloudTrail ConsoleLogin

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.004/aws_login_sfa/cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/aws_successful_single_factor_authentication.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
