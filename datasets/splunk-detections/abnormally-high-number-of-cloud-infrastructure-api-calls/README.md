# Abnormally High Number Of Cloud Infrastructure API Calls

**Type:** Anomaly

**Author:** David Dorsey, Splunk

## Description

This dataset contains sample data for detecting a spike in the number of API calls made to your cloud infrastructure by a user. It leverages cloud infrastructure logs and compares the current API call volume against a baseline probability density function to identify anomalies. This activity is significant because an unusual increase in API calls can indicate potential misuse or compromise of cloud resources. If confirmed malicious, this could lead to unauthorized access, data exfiltration, or disruption of cloud services, posing a significant risk to the organization's cloud environment.

## MITRE ATT&CK

- T1078.004

## Analytic Stories

- Suspicious Cloud User Activities
- Compromised User Account
- Scattered Lapsus$ Hunters

## Data Sources

- AWS CloudTrail

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json


---

*Source: [Splunk Security Content](detections/cloud/abnormally_high_number_of_cloud_infrastructure_api_calls.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
