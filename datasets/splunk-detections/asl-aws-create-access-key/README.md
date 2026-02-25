# ASL AWS Create Access Key

**Type:** Hunting

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for identifying the creation of AWS IAM access keys by a user for another user, which can indicate privilege escalation. It leverages AWS CloudTrail logs to detect instances where the user creating the access key is different from the user for whom the key is created. This activity is significant because unauthorized access key creation can allow attackers to establish persistence or exfiltrate data via AWS APIs. If confirmed malicious, this could lead to unauthorized access to AWS services, data exfiltration, and long-term persistence in the environment.

## MITRE ATT&CK

- T1136.003

## Analytic Stories

- AWS IAM Privilege Escalation
- Scattered Lapsus$ Hunters

## Data Sources

- ASL AWS CloudTrail

## Sample Data

- **Source:** aws_asl
  **Sourcetype:** aws:asl
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/aws_createaccesskey/asl_ocsf_cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/asl_aws_create_access_key.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
