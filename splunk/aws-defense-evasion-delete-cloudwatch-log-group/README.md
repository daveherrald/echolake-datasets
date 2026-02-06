# AWS Defense Evasion Delete CloudWatch Log Group

**Type:** TTP

**Author:** Gowthamaraj Rajendran, Splunk

## Description

The following analytic detects the deletion of CloudWatch log groups in AWS, identified through `DeleteLogGroup` events in CloudTrail logs. This detection leverages CloudTrail data to monitor for successful log group deletions, excluding console-based actions. This activity is significant as it indicates potential attempts to evade logging and monitoring, which is crucial for maintaining visibility into AWS activities. If confirmed malicious, this could allow attackers to hide their tracks, making it difficult to detect further malicious actions or investigate incidents within the compromised AWS environment.

## MITRE ATT&CK

- T1562.008

## Analytic Stories

- AWS Defense Evasion

## Data Sources

- AWS CloudTrail DeleteLogGroup

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.008/delete_cloudwatch_log_group/aws_cloudtrail_events.json


---

*Source: [Splunk Security Content](detections/cloud/aws_defense_evasion_delete_cloudwatch_log_group.yml)*
