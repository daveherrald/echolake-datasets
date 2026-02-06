# Cloud Compute Instance Created With Previously Unseen Image

**Type:** Anomaly

**Author:** David Dorsey, Splunk

## Description

The following analytic detects the creation of cloud compute instances using previously unseen image IDs. It leverages cloud infrastructure logs to identify new image IDs that have not been observed before. This activity is significant because it may indicate unauthorized or suspicious activity, such as the deployment of malicious payloads or unauthorized access to sensitive information. If confirmed malicious, this could lead to data breaches, unauthorized access, or further compromise of the cloud environment. Immediate investigation is required to determine the legitimacy of the instance creation and to mitigate potential threats.

## Analytic Stories

- Cloud Cryptomining

## Data Sources

- AWS CloudTrail

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json


---

*Source: [Splunk Security Content](detections/cloud/cloud_compute_instance_created_with_previously_unseen_image.yml)*
