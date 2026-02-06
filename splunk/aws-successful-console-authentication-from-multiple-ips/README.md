# AWS Successful Console Authentication From Multiple IPs

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

The following analytic detects an AWS account successfully authenticating from multiple unique IP addresses within a 5-minute window. It leverages AWS CloudTrail logs, specifically monitoring `ConsoleLogin` events and counting distinct source IPs. This behavior is significant as it may indicate compromised credentials, potentially from a phishing attack, being used concurrently by an adversary and a legitimate user. If confirmed malicious, this activity could allow unauthorized access to corporate resources, leading to data breaches or further exploitation within the AWS environment.

## MITRE ATT&CK

- T1586
- T1535

## Analytic Stories

- Suspicious AWS Login Activities
- Compromised User Account

## Data Sources

- AWS CloudTrail ConsoleLogin

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1586.003/aws_console_login_multiple_ips/cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/aws_successful_console_authentication_from_multiple_ips.yml)*
