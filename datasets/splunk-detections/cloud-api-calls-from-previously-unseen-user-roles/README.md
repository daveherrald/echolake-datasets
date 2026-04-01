# Cloud API Calls From Previously Unseen User Roles

**Type:** Anomaly

**Author:** David Dorsey, Splunk

## Description

This dataset contains sample data for detecting cloud API calls executed by user roles that have not previously run these commands. It leverages the Change data model in Splunk to identify commands executed by users with the user_type of AssumedRole and a status of success. This activity is significant because new commands from different user roles can indicate potential malicious activity or unauthorized actions. If confirmed malicious, this behavior could lead to unauthorized access, data breaches, or other damaging outcomes by exploiting new or unmonitored commands within the cloud environment.

## MITRE ATT&CK

- T1078

## Analytic Stories

- Suspicious Cloud User Activities

## Data Sources

- AWS CloudTrail

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json


---

*Source: [Splunk Security Content](detections/cloud/cloud_api_calls_from_previously_unseen_user_roles.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
