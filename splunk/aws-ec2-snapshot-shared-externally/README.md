# AWS EC2 Snapshot Shared Externally

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

The following analytic detects when an EC2 snapshot is shared with an external AWS account by analyzing AWS CloudTrail events. This detection method leverages CloudTrail logs to identify modifications in snapshot permissions, specifically when the snapshot is shared outside the originating AWS account. This activity is significant as it may indicate an attempt to exfiltrate sensitive data stored in the snapshot. If confirmed malicious, an attacker could gain unauthorized access to the snapshot's data, potentially leading to data breaches or further exploitation of the compromised information.

## MITRE ATT&CK

- T1537

## Analytic Stories

- Suspicious Cloud Instance Activities
- Data Exfiltration

## Data Sources

- AWS CloudTrail ModifySnapshotAttribute

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1537/aws_snapshot_exfil/aws_cloudtrail_events.json


---

*Source: [Splunk Security Content](detections/cloud/aws_ec2_snapshot_shared_externally.yml)*
