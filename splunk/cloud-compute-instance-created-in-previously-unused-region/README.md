# Cloud Compute Instance Created In Previously Unused Region

**Type:** Anomaly

**Author:** David Dorsey, Splunk

## Description

The following analytic detects the creation of a cloud compute instance in a region that has not been previously used within the last hour. It leverages cloud infrastructure logs and compares the regions of newly created instances against a lookup file of historically used regions. This activity is significant because the creation of instances in new regions can indicate unauthorized or suspicious activity, such as an attacker attempting to evade detection or establish a foothold in a less monitored area. If confirmed malicious, this could lead to unauthorized resource usage, data exfiltration, or further compromise of the cloud environment.

## MITRE ATT&CK

- T1535

## Analytic Stories

- Cloud Cryptomining

## Data Sources

- AWS CloudTrail

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json


---

*Source: [Splunk Security Content](detections/cloud/cloud_compute_instance_created_in_previously_unused_region.yml)*
