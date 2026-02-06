# ASL AWS Network Access Control List Deleted

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects the deletion of AWS Network Access Control Lists (ACLs). It leverages AWS CloudTrail logs to identify events where a user deletes a network ACL entry. This activity is significant because deleting a network ACL can remove critical access restrictions, potentially allowing unauthorized access to cloud instances. If confirmed malicious, this action could enable attackers to bypass network security controls, leading to unauthorized access, data exfiltration, or further compromise of the cloud environment.

## MITRE ATT&CK

- T1562.007

## Analytic Stories

- AWS Network ACL Activity
- Scattered Lapsus$ Hunters

## Data Sources

- ASL AWS CloudTrail

## Sample Data

- **Source:** aws_asl
  **Sourcetype:** aws:asl
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.007/aws_delete_acl/asl_ocsf_cloudtrail.json


---

*Source: [Splunk Security Content](detections/cloud/asl_aws_network_access_control_list_deleted.yml)*
