# Cloud Compute Instance Created By Previously Unseen User

**Type:** Anomaly

**Author:** Rico Valdez, Splunk

## Description

The following analytic identifies the creation of cloud compute instances by users who have not previously created them. It leverages data from the Change data model, focusing on 'create' actions by users, and cross-references with a baseline of known user activities. This activity is significant as it may indicate unauthorized access or misuse of cloud resources by new or compromised accounts. If confirmed malicious, attackers could deploy unauthorized compute instances, leading to potential data exfiltration, increased costs, or further exploitation within the cloud environment.

## MITRE ATT&CK

- T1078.004

## Analytic Stories

- Cloud Cryptomining

## Data Sources

- AWS CloudTrail

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json


---

*Source: [Splunk Security Content](detections/cloud/cloud_compute_instance_created_by_previously_unseen_user.yml)*
