# AWS Console Login Failed During MFA Challenge

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

The following analytic identifies failed authentication attempts to the AWS Console during the Multi-Factor Authentication (MFA) challenge. It leverages AWS CloudTrail logs, specifically the `additionalEventData` field, to detect when MFA was used but the login attempt still failed. This activity is significant as it may indicate an adversary attempting to access an account with compromised credentials but being thwarted by MFA. If confirmed malicious, this could suggest an ongoing attempt to breach the account, potentially leading to unauthorized access and further attacks if MFA is bypassed.

## MITRE ATT&CK

- T1586.003
- T1621

## Analytic Stories

- AWS Identity and Access Management Account Takeover
- Compromised User Account

## Data Sources

- AWS CloudTrail ConsoleLogin

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/aws_failed_mfa/cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/aws_console_login_failed_during_mfa_challenge.yml)*
