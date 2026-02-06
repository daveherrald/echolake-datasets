# AWS Excessive Security Scanning

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic identifies excessive security scanning activities in AWS by detecting a high number of Describe, List, or Get API calls from a single user. It leverages AWS CloudTrail logs to count distinct event names and flags users with more than 50 such events. This behavior is significant as it may indicate reconnaissance activities by an attacker attempting to map out your AWS environment. If confirmed malicious, this could lead to unauthorized access, data exfiltration, or further exploitation of your cloud infrastructure.

## MITRE ATT&CK

- T1526

## Analytic Stories

- AWS User Monitoring

## Data Sources

- AWS CloudTrail

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1526/aws_security_scanner/aws_security_scanner.json


---

*Source: [Splunk Security Content](detections/cloud/aws_excessive_security_scanning.yml)*
