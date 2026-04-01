# AWS Network Access Control List Created with All Open Ports

**Type:** TTP

**Author:** Bhavin Patel, Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting the creation of AWS Network Access Control Lists (ACLs) with all ports open to a specified CIDR. It leverages AWS CloudTrail events, specifically monitoring for `CreateNetworkAclEntry` or `ReplaceNetworkAclEntry` actions with rules allowing all traffic. This activity is significant because it can expose the network to unauthorized access, increasing the risk of data breaches and other malicious activities. If confirmed malicious, an attacker could exploit this misconfiguration to gain unrestricted access to the network, potentially leading to data exfiltration, service disruption, or further compromise of the AWS environment.

## MITRE ATT&CK

- T1562.007

## Analytic Stories

- AWS Network ACL Activity

## Data Sources

- AWS CloudTrail CreateNetworkAclEntry
- AWS CloudTrail ReplaceNetworkAclEntry

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.007/aws_create_acl/aws_cloudtrail_events.json


---

*Source: [Splunk Security Content](detections/cloud/aws_network_access_control_list_created_with_all_open_ports.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
