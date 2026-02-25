# AWS CreateAccessKey

**Type:** Hunting

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for identifying the creation of AWS IAM access keys by a user for another user, which can indicate privilege escalation. It leverages AWS CloudTrail logs to detect instances where the user creating the access key is different from the user for whom the key is created. This activity is significant because unauthorized access key creation can allow attackers to establish persistence or exfiltrate data via AWS APIs. If confirmed malicious, this could lead to unauthorized access to AWS services, data exfiltration, and long-term persistence in the environment.

## MITRE ATT&CK

- T1136.003

## Analytic Stories

- AWS IAM Privilege Escalation

## Data Sources

- AWS CloudTrail CreateAccessKey

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/aws_createaccesskey/aws_cloudtrail_events.json


---

*Source: [Splunk Security Content](detections/cloud/aws_createaccesskey.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
