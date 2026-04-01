# Cloud Provisioning Activity From Previously Unseen IP Address

**Type:** Anomaly

**Author:** Rico Valdez, Splunk

## Description

This dataset contains sample data for detecting cloud provisioning activities originating from previously unseen IP addresses. It leverages cloud infrastructure logs to identify events where resources are created or started, and cross-references these with a baseline of known IP addresses. This activity is significant as it may indicate unauthorized access or potential misuse of cloud resources. If confirmed malicious, an attacker could gain unauthorized control over cloud resources, leading to data breaches, service disruptions, or increased operational costs.

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

*Source: [Splunk Security Content](detections/cloud/cloud_provisioning_activity_from_previously_unseen_ip_address.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
