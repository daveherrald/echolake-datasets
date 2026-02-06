# Cloud Provisioning Activity From Previously Unseen City

**Type:** Anomaly

**Author:** Rico Valdez, Bhavin Patel, Splunk

## Description

The following analytic detects cloud provisioning activities originating from previously unseen cities. It leverages cloud infrastructure logs and compares the geographic location of the source IP address against a baseline of known locations. This activity is significant as it may indicate unauthorized access or misuse of cloud resources from an unexpected location. If confirmed malicious, this could lead to unauthorized resource creation, potential data exfiltration, or further compromise of cloud infrastructure.

## MITRE ATT&CK

- T1078

## Analytic Stories

- Suspicious Cloud Provisioning Activities

## Data Sources

- AWS CloudTrail

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json


---

*Source: [Splunk Security Content](detections/cloud/cloud_provisioning_activity_from_previously_unseen_city.yml)*
