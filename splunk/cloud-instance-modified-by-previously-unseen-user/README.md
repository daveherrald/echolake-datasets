# Cloud Instance Modified By Previously Unseen User

**Type:** Anomaly

**Author:** Rico Valdez, Splunk

## Description

The following analytic identifies cloud instances being modified by users who have not previously modified them. It leverages data from the Change data model, focusing on successful modifications of EC2 instances. This activity is significant because it can indicate unauthorized or suspicious changes by potentially compromised or malicious users. If confirmed malicious, this could lead to unauthorized access, configuration changes, or potential disruption of cloud services, posing a significant risk to the organization's cloud infrastructure.

## MITRE ATT&CK

- T1078.004

## Analytic Stories

- Suspicious Cloud Instance Activities

## Data Sources

- AWS CloudTrail

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json


---

*Source: [Splunk Security Content](detections/cloud/cloud_instance_modified_by_previously_unseen_user.yml)*
