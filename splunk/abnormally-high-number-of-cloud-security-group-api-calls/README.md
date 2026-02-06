# Abnormally High Number Of Cloud Security Group API Calls

**Type:** Anomaly

**Author:** David Dorsey, Splunk

## Description

The following analytic detects a spike in the number of API calls made to cloud security groups by a user. It leverages data from the Change data model, focusing on successful firewall-related changes. This activity is significant because an abnormal increase in security group API calls can indicate potential malicious activity, such as unauthorized access or configuration changes. If confirmed malicious, this could allow an attacker to manipulate security group settings, potentially exposing sensitive resources or disrupting network security controls.

## MITRE ATT&CK

- T1078.004

## Analytic Stories

- Suspicious Cloud User Activities

## Data Sources

- AWS CloudTrail

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/abnormally_high_cloud_instances_launched/cloudtrail_behavioural_detections.json


---

*Source: [Splunk Security Content](detections/cloud/abnormally_high_number_of_cloud_security_group_api_calls.yml)*
