# AWS IAM AccessDenied Discovery Events

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying excessive AccessDenied events within an hour timeframe for IAM users in AWS. It leverages AWS CloudTrail logs to detect multiple failed access attempts from the same source IP and user identity. This activity is significant as it may indicate that an access key has been compromised and is being misused for unauthorized discovery actions. If confirmed malicious, this could allow attackers to gather information about the AWS environment, potentially leading to further exploitation or privilege escalation.

## MITRE ATT&CK

- T1580

## Analytic Stories

- Suspicious Cloud User Activities

## Data Sources

- AWS CloudTrail

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1580/aws_iam_accessdenied_discovery_events/aws_iam_accessdenied_discovery_events.json


---

*Source: [Splunk Security Content](detections/cloud/aws_iam_accessdenied_discovery_events.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
