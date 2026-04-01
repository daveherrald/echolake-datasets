# ASL AWS Credential Access GetPasswordData

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for identifyingGetPasswordData API calls in your AWS account. It leverages  CloudTrail logs from Amazon Security Lake to detect this activity by counting the distinct instance IDs accessed. This behavior is significant as it may indicate an attempt to retrieve encrypted administrator passwords for running Windows instances, which is a critical security concern. If confirmed malicious, attackers could gain unauthorized access to administrative credentials, potentially leading to full control over the affected instances and further compromise of the AWS environment.

## MITRE ATT&CK

- T1110.001
- T1586.003

## Analytic Stories

- AWS Identity and Access Management Account Takeover

## Data Sources

- ASL AWS CloudTrail

## Sample Data

- **Source:** aws_asl
  **Sourcetype:** aws:asl
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552/aws_getpassworddata/asl_ocsf_cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/asl_aws_credential_access_getpassworddata.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
