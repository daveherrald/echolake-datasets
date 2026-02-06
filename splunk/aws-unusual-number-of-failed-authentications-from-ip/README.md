# AWS Unusual Number of Failed Authentications From Ip

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

The following analytic identifies a single source IP failing to authenticate into the AWS Console with multiple valid users. It uses CloudTrail logs and calculates the standard deviation for source IP, leveraging the 3-sigma rule to detect unusual numbers of failed authentication attempts. This behavior is significant as it may indicate a Password Spraying attack, where an adversary attempts to gain initial access or elevate privileges. If confirmed malicious, this activity could lead to unauthorized access, data breaches, or further exploitation within the AWS environment.

## MITRE ATT&CK

- T1110.003
- T1110.004
- T1586.003

## Analytic Stories

- AWS Identity and Access Management Account Takeover

## Data Sources

- AWS CloudTrail ConsoleLogin

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/aws_mulitple_failed_console_login/aws_cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/aws_unusual_number_of_failed_authentications_from_ip.yml)*
