# AWS ECR Container Scanning Findings High

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for identifying high-severity findings from AWS Elastic Container Registry (ECR) image scans. It detects these activities by analyzing AWS CloudTrail logs for the DescribeImageScanFindings event, specifically filtering for findings with a high severity level. This activity is significant for a SOC because high-severity vulnerabilities in container images can lead to potential exploitation if not addressed. If confirmed malicious, attackers could exploit these vulnerabilities to gain unauthorized access, execute arbitrary code, or escalate privileges within the container environment, posing a significant risk to the overall security posture.

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

*Source: [Splunk Security Content](detections/cloud/aws_ecr_container_scanning_findings_high.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
