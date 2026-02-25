# AWS Exfiltration via DataSync Task

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for detecting the creation of an AWS DataSync task, which could indicate potential data exfiltration. It leverages AWS CloudTrail logs to identify the `CreateTask` event from the DataSync service. This activity is significant because attackers can misuse DataSync to transfer sensitive data from a private AWS location to a public one, leading to data compromise. If confirmed malicious, this could result in unauthorized access to sensitive information, causing severe data breaches and compliance violations.

## MITRE ATT&CK

- T1119

## Analytic Stories

- Suspicious AWS S3 Activities
- Data Exfiltration
- Hellcat Ransomware

## Data Sources

- AWS CloudTrail CreateTask

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1119/aws_exfil_datasync/cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/aws_exfiltration_via_datasync_task.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
