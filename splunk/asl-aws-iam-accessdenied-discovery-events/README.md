# ASL AWS IAM AccessDenied Discovery Events

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic identifies excessive AccessDenied events within an hour timeframe for IAM users in AWS. It leverages AWS CloudTrail logs to detect multiple failed access attempts from the same source IP and user identity. This activity is significant as it may indicate that an access key has been compromised and is being misused for unauthorized discovery actions. If confirmed malicious, this could allow attackers to gather information about the AWS environment, potentially leading to further exploitation or privilege escalation.

## MITRE ATT&CK

- T1580

## Analytic Stories

- Suspicious Cloud User Activities

## Data Sources

- ASL AWS CloudTrail

## Sample Data

- **Source:** aws_asl
  **Sourcetype:** aws:asl
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1580/aws_iam_accessdenied_discovery_events/asl_ocsf_cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/asl_aws_iam_accessdenied_discovery_events.yml)*
