# AWS CreateLoginProfile

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

The following analytic identifies the creation of a login profile for one AWS user by another, followed by a console login from the same source IP. It uses AWS CloudTrail logs to correlate the `CreateLoginProfile` and `ConsoleLogin` events based on the source IP and user identity. This activity is significant as it may indicate privilege escalation, where an attacker creates a new login profile to gain unauthorized access. If confirmed malicious, this could allow the attacker to escalate privileges and maintain persistent access to the AWS environment.

## MITRE ATT&CK

- T1136.003

## Analytic Stories

- AWS IAM Privilege Escalation

## Data Sources

- AWS CloudTrail CreateLoginProfile AND AWS CloudTrail ConsoleLogin

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/aws_createloginprofile/aws_cloudtrail_events.json


---

*Source: [Splunk Security Content](detections/cloud/aws_createloginprofile.yml)*
