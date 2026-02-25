# ASL AWS Defense Evasion Delete CloudWatch Log Group

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting the deletion of CloudWatch log groups in AWS, identified through `DeleteLogGroup` events in CloudTrail logs. This method leverages Amazon Security Lake logs parsed in the OCSF format. The activity is significant because attackers may delete log groups to evade detection and disrupt logging capabilities, hindering incident response efforts. If confirmed malicious, this action could allow attackers to cover their tracks, making it difficult to trace their activities and potentially leading to undetected data breaches or further malicious actions within the compromised AWS environment.

## MITRE ATT&CK

- T1562.008

## Analytic Stories

- AWS Defense Evasion

## Data Sources

- ASL AWS CloudTrail

## Sample Data

- **Source:** aws_asl
  **Sourcetype:** aws:asl
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.008/delete_cloudwatch_log_group/asl_ocsf_cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/asl_aws_defense_evasion_delete_cloudwatch_log_group.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
