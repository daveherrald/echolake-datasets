# AWS ECR Container Scanning Findings Medium

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic identifies medium-severity findings from AWS Elastic Container Registry (ECR) image scans. It leverages AWS CloudTrail logs, specifically the DescribeImageScanFindings event, to detect vulnerabilities in container images. This activity is significant for a SOC as it highlights potential security risks in containerized applications, which could be exploited if not addressed. If confirmed malicious, these vulnerabilities could lead to unauthorized access, data breaches, or further exploitation within the container environment, compromising the overall security posture.

## MITRE ATT&CK

- T1204.003

## Analytic Stories

- Dev Sec Ops

## Data Sources

- AWS CloudTrail DescribeImageScanFindings

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1204.003/aws_ecr_image_scanning/aws_ecr_scanning_findings_events.json


---

*Source: [Splunk Security Content](detections/cloud/aws_ecr_container_scanning_findings_medium.yml)*
