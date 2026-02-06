# Cloud Provisioning Activity From Previously Unseen Country

**Type:** Anomaly

**Author:** Rico Valdez, Bhavin Patel, Splunk

## Description

The following analytic detects cloud provisioning activities originating from previously unseen countries. It leverages cloud infrastructure logs and compares the geographic location of the source IP address against a baseline of known locations. This activity is significant as it may indicate unauthorized access or potential compromise of cloud resources. If confirmed malicious, an attacker could gain control over cloud assets, leading to data breaches, service disruptions, or further infiltration into the network.

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

*Source: [Splunk Security Content](detections/cloud/cloud_provisioning_activity_from_previously_unseen_country.yml)*
