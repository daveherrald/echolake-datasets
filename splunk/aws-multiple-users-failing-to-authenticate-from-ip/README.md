# AWS Multiple Users Failing To Authenticate From Ip

**Type:** Anomaly

**Author:** Bhavin Patel

## Description

The following analytic identifies a single source IP failing to authenticate into the AWS Console with 30 unique valid users within 10 minutes. It leverages CloudTrail logs to detect multiple failed login attempts from the same IP address. This behavior is significant as it may indicate a Password Spraying attack, where an adversary attempts to gain unauthorized access or elevate privileges by trying common passwords across many accounts. If confirmed malicious, this activity could lead to unauthorized access, data breaches, or further exploitation within the AWS environment.

## MITRE ATT&CK

- T1110.003
- T1110.004

## Analytic Stories

- AWS Identity and Access Management Account Takeover
- Compromised User Account

## Data Sources

- AWS CloudTrail ConsoleLogin

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/aws_mulitple_failed_console_login/aws_cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/aws_multiple_users_failing_to_authenticate_from_ip.yml)*
