# Cloud Provisioning Activity From Previously Unseen Region

**Type:** Anomaly

**Author:** Rico Valdez, Bhavin Patel, Splunk

## Description

The following analytic detects cloud provisioning activities originating from previously unseen regions. It leverages cloud infrastructure logs to identify events where resources are started or created, and cross-references these with a baseline of known regions. This activity is significant as it may indicate unauthorized access or misuse of cloud resources from unfamiliar locations. If confirmed malicious, this could lead to unauthorized resource creation, potential data exfiltration, or further compromise of cloud infrastructure.

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

*Source: [Splunk Security Content](detections/cloud/cloud_provisioning_activity_from_previously_unseen_region.yml)*
