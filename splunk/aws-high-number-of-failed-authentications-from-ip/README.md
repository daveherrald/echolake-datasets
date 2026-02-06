# AWS High Number Of Failed Authentications From Ip

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

The following analytic detects an IP address with 20 or more failed authentication attempts to the AWS Web Console within a 5-minute window. This detection leverages CloudTrail logs, aggregating failed login events by IP address and time span. This activity is significant as it may indicate a brute force attack aimed at gaining unauthorized access or escalating privileges within an AWS environment. If confirmed malicious, this could lead to unauthorized access, data breaches, or further exploitation of AWS resources.

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

*Source: [Splunk Security Content](detections/cloud/aws_high_number_of_failed_authentications_from_ip.yml)*
