# AWS Network Access Control List Deleted

**Type:** Anomaly

**Author:** Bhavin Patel, Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting the deletion of AWS Network Access Control Lists (ACLs). It leverages AWS CloudTrail logs to identify events where a user deletes a network ACL entry. This activity is significant because deleting a network ACL can remove critical access restrictions, potentially allowing unauthorized access to cloud instances. If confirmed malicious, this action could enable attackers to bypass network security controls, leading to unauthorized access, data exfiltration, or further compromise of the cloud environment.

## MITRE ATT&CK

- T1562.007

## Analytic Stories

- AWS Network ACL Activity

## Data Sources

- AWS CloudTrail DeleteNetworkAclEntry

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.007/aws_delete_acl/aws_cloudtrail_events.json


---

*Source: [Splunk Security Content](detections/cloud/aws_network_access_control_list_deleted.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
