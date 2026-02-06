# Cloud Compute Instance Created With Previously Unseen Instance Type

**Type:** Anomaly

**Author:** David Dorsey, Splunk

## Description

The following analytic detects the creation of EC2 instances with previously unseen instance types. It leverages Splunk's tstats command to analyze data from the Change data model, identifying instance types that have not been previously recorded. This activity is significant for a SOC because it may indicate unauthorized or suspicious activity, such as an attacker attempting to create instances for malicious purposes. If confirmed malicious, this could lead to unauthorized access, data exfiltration, system compromise, or service disruption. Immediate investigation is required to determine the legitimacy of the instance creation.

## Analytic Stories

- Cloud Cryptomining

## Data Sources

- AWS CloudTrail

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json


---

*Source: [Splunk Security Content](detections/cloud/cloud_compute_instance_created_with_previously_unseen_instance_type.yml)*
