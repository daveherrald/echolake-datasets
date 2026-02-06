# AWS Concurrent Sessions From Different Ips

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

The following analytic identifies an AWS IAM account with concurrent sessions originating from more than one unique IP address within a 5-minute window. It leverages AWS CloudTrail logs, specifically the `DescribeEventAggregates` event, to detect this behavior. This activity is significant as it may indicate a session hijacking attack, where an adversary uses stolen session cookies to access AWS resources from a different location. If confirmed malicious, this could allow unauthorized access to sensitive corporate resources, leading to potential data breaches or further exploitation within the AWS environment.

## MITRE ATT&CK

- T1185

## Analytic Stories

- Compromised User Account
- AWS Identity and Access Management Account Takeover
- Scattered Lapsus$ Hunters

## Data Sources

- AWS CloudTrail DescribeEventAggregates

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1185/aws_concurrent_sessions_from_different_ips/cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/aws_concurrent_sessions_from_different_ips.yml)*
