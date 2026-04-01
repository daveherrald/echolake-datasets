# AWS Defense Evasion Update Cloudtrail

**Type:** TTP

**Author:** Gowthamaraj Rajendran, Splunk

## Description

This dataset contains sample data for detecting `UpdateTrail` events in AWS CloudTrail logs. It identifies attempts to modify CloudTrail settings, potentially to evade logging. The detection leverages CloudTrail logs, focusing on `UpdateTrail` events where the user agent is not the AWS console and the operation is successful. This activity is significant because altering CloudTrail settings can disable or limit logging, hindering visibility into AWS account activities. If confirmed malicious, this could allow attackers to operate undetected, compromising the integrity and security of the AWS environment.

## MITRE ATT&CK

- T1562.008

## Analytic Stories

- AWS Defense Evasion

## Data Sources

- AWS CloudTrail UpdateTrail

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.008/update_cloudtrail/aws_cloudtrail_events.json


---

*Source: [Splunk Security Content](detections/cloud/aws_defense_evasion_update_cloudtrail.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
