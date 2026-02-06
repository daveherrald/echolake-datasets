# AWS ECR Container Scanning Findings Low Informational Unknown

**Type:** Anomaly

**Author:** Patrick Bareiss, Eric McGinnis Splunk

## Description

The following analytic identifies low, informational, or unknown severity findings from AWS Elastic Container Registry (ECR) image scans. It leverages AWS CloudTrail logs, specifically the DescribeImageScanFindings event, to detect these findings. This activity is significant for a SOC as it helps in early identification of potential vulnerabilities or misconfigurations in container images, which could be exploited if left unaddressed. If confirmed malicious, these findings could lead to unauthorized access, data breaches, or further exploitation within the containerized environment.

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

*Source: [Splunk Security Content](detections/cloud/aws_ecr_container_scanning_findings_low_informational_unknown.yml)*
