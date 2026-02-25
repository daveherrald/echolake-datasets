# AWS Exfiltration via EC2 Snapshot

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for detecting a series of AWS API calls related to EC2 snapshots within a short time window, indicating potential exfiltration via EC2 Snapshot modifications. It leverages AWS CloudTrail logs to identify actions such as creating, describing, and modifying snapshot attributes. This activity is significant as it may indicate an attacker attempting to exfiltrate data by sharing EC2 snapshots externally. If confirmed malicious, the attacker could gain access to sensitive information stored in the snapshots, leading to data breaches and potential compliance violations.

## MITRE ATT&CK

- T1537

## Analytic Stories

- Suspicious Cloud Instance Activities
- Data Exfiltration

## Data Sources

- AWS CloudTrail CreateSnapshot
- AWS CloudTrail DescribeSnapshotAttribute
- AWS CloudTrail ModifySnapshotAttribute
- AWS CloudTrail DeleteSnapshot

## Sample Data

- **Source:** aws_cloudtrail
  **Sourcetype:** aws:cloudtrail
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1537/aws_snapshot_exfil/aws_cloudtrail_events.json


---

*Source: [Splunk Security Content](detections/cloud/aws_exfiltration_via_ec2_snapshot.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
